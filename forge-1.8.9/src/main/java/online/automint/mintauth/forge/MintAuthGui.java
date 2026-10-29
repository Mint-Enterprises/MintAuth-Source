// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.forge;

import net.minecraft.client.gui.*;
import net.minecraft.client.renderer.GlStateManager;
import net.minecraft.client.renderer.texture.DynamicTexture;
import net.minecraft.util.ResourceLocation;

import online.automint.mintauth.core.AccountPreparation;
import online.automint.mintauth.core.MintAuthRuntime;
import online.automint.mintauth.core.MintLoadingAnimation;

import org.lwjgl.input.Keyboard;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import javax.imageio.ImageIO;

public final class MintAuthGui extends GuiScreen implements GuiYesNoCallback {
    private enum Step {
        STARTING,
        HOME,
        ADD,
        CONNECT,
        IMPORT,
        WORKING,
        READY,
        ERROR,
        UNLOCK,
        PASSWORD,
        RECOVERY,
        SYNC,
        MOVE,
        SETTINGS,
        APPEARANCE,
        UPDATES,
        DEVICE,
        ADVANCED,
        MANAGE,
        DETAILS,
        ACCOUNT_ACTIONS,
        CREDENTIALS
    }

    private enum Job {
        NONE,
        STORAGE,
        LINK,
        IMPORT,
        SELECT,
        REFRESH,
        SYNC,
        UNLOCK,
        RESET,
        REMOVE,
        CLEAR
    }

    private final GuiScreen parent;
    private final Map<Integer, Runnable> actions = new HashMap<>();
    private Step step = Step.STARTING, resume = Step.HOME, errorReturn = Step.HOME;
    private Job job = Job.NONE;
    private String selected, signature = "", localError;
    private SecretField secret, repeat;
    private char[] draft;
    private MintButton primary, websiteButton;
    private boolean cloud = true, browserOpened;
    private int next = 1, page, left, span, footer, focus = -1;
    private long ticket, applyDeadline;
    private AccountPreparation preparation;
    private long animationStarted = System.nanoTime();
    private Runnable confirmation;
    private static ResourceLocation logo;

    public MintAuthGui(GuiScreen parent) {
        this.parent = parent;
        if (rt() != null) rt().logUiStep(step.name());
    }

    private MintAuthRuntime rt() {
        return MintAuthMod.runtime();
    }

    private Runnable tracedAction(Runnable action) {
        return () -> {
            if (rt() != null) rt().logUiAction();
            try {
                action.run();
            } catch (RuntimeException | LinkageError error) {
                if (rt() != null) rt().logUiFailure(error);
                throw error;
            }
        };
    }

    private MintButton button(String label, int x, int y, int w, Runnable action) {
        MintButton b = new MintButton(next++, x, y, w, 22, label);
        buttonList.add(b);
        actions.put(b.id, tracedAction(action));
        return b;
    }

    private MintButton action(String label, int y, Runnable action) {
        return button(label, left, y, span, action);
    }

    private void primary(String label, int y, Runnable action) {
        primary = action(label, y, action).primary();
    }

    private void quiet(String label, int x, int y, int w, Runnable action) {
        button(label, x, y, w, action).quiet();
    }

    private void clearInput() {
        if (secret != null) secret.setText("");
        if (repeat != null) repeat.setText("");
        secret = null;
        repeat = null;
    }

    private void clearDraft() {
        if (draft != null) Arrays.fill(draft, '\0');
        draft = null;
    }

    private void go(Step target) {
        if (rt() != null) rt().logUiStep(target.name());
        if (target == Step.IMPORT && step != Step.IMPORT) rt().clearSecureWebsiteNotice();
        clearInput();
        step = target;
        localError = null;
        focus = -1;
        initGui();
    }

    private void preserveInput() {
        String value = secret == null ? null : secret.getText();
        initGui();
        if (secret != null && value != null) secret.setText(value);
    }

    private void close() {
        if (job == Job.SELECT) rt().cancelPreparation();
        clearInput();
        clearDraft();
        if (rt() != null) rt().dismissWelcome();
        mc.displayGuiScreen(parent);
    }

    private void back() {
        if (step == Step.WORKING) {
            if (job == Job.SELECT) rt().cancelPreparation();
            else return;
            job = Job.NONE;
            go(Step.HOME);
            return;
        }
        clearDraft();
        switch (step) {
            case STARTING:
            case HOME:
                close();
                break;
            case SETTINGS:
            case ADD:
            case IMPORT:
            case CONNECT:
            case READY:
            case ERROR:
            case MOVE:
            case SYNC:
                go(Step.HOME);
                break;
            case UNLOCK:
            case PASSWORD:
            case RECOVERY:
                go(Step.HOME);
                break;
            case APPEARANCE:
            case UPDATES:
            case DEVICE:
            case MANAGE:
                go(Step.SETTINGS);
                break;
            case ADVANCED:
                go(Step.DEVICE);
                break;
            case DETAILS:
                go(Step.MANAGE);
                break;
            case ACCOUNT_ACTIONS:
            case CREDENTIALS:
                go(Step.DETAILS);
                break;
            default:
                go(Step.HOME);
        }
    }

    private void work(Job kind, Step failure, Runnable action) {
        localError = null;
        applyDeadline = 0;
        errorReturn = failure;
        job = kind;
        animationStarted = System.nanoTime();
        long before = rt().submittedOperation();
        action.run();
        preparation = kind == Job.SELECT ? rt().preparation() : null;
        ticket = rt().submittedOperation();
        if (ticket <= before) {
            job = Job.NONE;
            go(failure);
            return;
        }
        go(Step.WORKING);
    }

    private void prepare(Step purpose) {
        rt().dismissWelcome();
        resume = purpose;
        if (rt().needsPassword()) {
            storageGate();
            return;
        }
        work(Job.STORAGE, Step.HOME, () -> rt().prepareGuidedStorage());
    }

    private void storageGate() {
        if ("VAULT_REVOKED".equals(rt().storageIssue())) go(Step.RECOVERY);
        else if ("PASSWORD_REQUIRED".equals(rt().storageIssue())) go(Step.UNLOCK);
        else go(Step.RECOVERY);
    }

    private void continueAfterStorage() {
        if (resume == Step.CONNECT) {
            browserOpened = false;
            go(Step.CONNECT);
            work(Job.LINK, Step.CONNECT, () -> rt().beginLink());
        } else go(resume);
    }

    private List<MintAuthRuntime.AccountView> accounts() {
        return rt() == null ? Collections.emptyList() : rt().accountCards();
    }

    private MintAuthRuntime.AccountView chosen() {
        return rt() == null ? null : rt().account(selected);
    }

    private int localCount() {
        int n = 0;
        for (MintAuthRuntime.AccountView a : rt().accounts()) if (a.needsSync) n++;
        return n;
    }

    private boolean available(MintAuthRuntime.AccountView a) {
        return a != null
                && (a.status == null
                        || "VALID".equals(a.status)
                        || "AVAILABLE".equals(a.status)
                        || (!"EXTERNAL".equals(a.kind) && "EXPIRED_REJECTED".equals(a.status)));
    }

    private String category(MintAuthRuntime.AccountView a) {
        return "OWNED".equals(a.kind)
                ? "Mint account"
                : "TEMPORARY".equals(a.kind) ? "Temporary access" : "Unverified";
    }

    private void choose(MintAuthRuntime.AccountView a) {
        if (a.id.equals(rt().playingAccountId())) return;
        preparation = null;
        selected = a.id;
        if (!available(a)) {
            go(Step.DETAILS);
            return;
        }
        work(Job.SELECT, Step.HOME, () -> rt().select(selected, false));
    }

    private void library(boolean manage) {
        boolean sources = step == Step.CREDENTIALS;
        int spacing = sources ? 28 : 48;
        int rows = Math.max(1, (height - 152) / spacing);
        List<MintAuthRuntime.AccountView> all =
                sources && chosen() != null ? rt().accountSources(chosen().uuid) : accounts();
        String playingId = rt().playingAccountId();
        page = Math.min(page, Math.max(0, (all.size() - 1) / rows));
        for (int i = page * rows; i < Math.min(all.size(), (page + 1) * rows); i++) {
            final MintAuthRuntime.AccountView a = all.get(i);
            boolean playing = sources ? a.id.equals(playingId) : rt().isPlaying(a);
            String label =
                    playing
                            ? "Playing: " + a.ign + " - " + rt().playingSourceLabel()
                            : a.ign
                                    + "  -  "
                                    + (sources && "EXTERNAL".equals(a.kind)
                                            ? (a.cloud ? "Saved SSID on AutoMint" : "Pasted SSID")
                                            : category(a))
                                    + (a.onAutoMint && !a.savedOnDevice ? " (on AutoMint)" : "")
                                    + (available(a) ? "" : " (unavailable)");
            MintButton row =
                    action(
                                    label,
                                    98 + (i - page * rows) * spacing,
                                    () -> {
                                        selected = a.id;
                                        if (manage) go(Step.DETAILS);
                                        else choose(a);
                                    })
                            .tab(playing);
            row.enabled = manage || !playing;
            if (!sources && playing && rt().canUseMintSession(a))
                button(
                                        "Use Mint session",
                                        left + span - 136,
                                        122 + (i - page * rows) * spacing,
                                        136,
                                        () -> choose(a))
                                .quiet()
                                .enabled =
                        rt().canSwitchIdentity();
        }
        if (all.size() > rows) {
            int y = height - 58;
            button(
                                    "<",
                                    left,
                                    y,
                                    32,
                                    () -> {
                                        page--;
                                        initGui();
                                    })
                            .enabled =
                    page > 0;
            button(
                                    ">",
                                    left + span - 32,
                                    y,
                                    32,
                                    () -> {
                                        page++;
                                        initGui();
                                    })
                            .enabled =
                    (page + 1) * rows < all.size();
        }
    }

    private SecretField field(int id, int y, int maximum) {
        SecretField f = new SecretField(id, fontRendererObj, left, y, span, 20);
        f.setMaxStringLength(maximum);
        return f;
    }

    private void confirm(String title, String text, Runnable action) {
        confirmation = action;
        mc.displayGuiScreen(new GuiYesNo(this, title, text, 0));
    }

    @Override
    public void confirmClicked(boolean yes, int id) {
        Runnable task = confirmation;
        confirmation = null;
        mc.displayGuiScreen(this);
        if (yes && task != null) task.run();
    }

    @Override
    public void initGui() {
        clearInput();
        buttonList.clear();
        actions.clear();
        primary = null;
        websiteButton = null;
        next = 1;
        focus = -1;
        Keyboard.enableRepeatEvents(true);
        span = Math.min(300, width - 32);
        left = (width - span) / 2;
        footer = height - 30;
        if (step == Step.STARTING && rt() != null && rt().startupReady()) step = Step.HOME;
        switch (step) {
            case STARTING:
                break;
            case HOME:
                if ("VAULT_REVOKED".equals(rt().storageIssue()))
                    primary(
                            "Set up again",
                            112,
                            () -> {
                                resume = Step.HOME;
                                work(Job.RESET, Step.HOME, () -> rt().resetClearedVault());
                            });
                else if (rt().needsPassword())
                    primary(
                            "Unlock your accounts",
                            112,
                            () -> {
                                resume = Step.HOME;
                                storageGate();
                            });
                else if (!accounts().isEmpty()) {
                    library(false);
                    quiet(
                            "Add account",
                            left + (span - 100) / 2,
                            footer,
                            100,
                            () -> {
                                if (rt().linked()) prepare(Step.IMPORT);
                                else go(Step.ADD);
                            });
                } else if (rt().linked()) {
                    primary(
                            "Refresh accounts",
                            112,
                            () -> work(Job.REFRESH, Step.HOME, () -> rt().refresh()));
                    action("Use an SSID", 142, () -> prepare(Step.IMPORT));
                } else {
                    primary("Link AutoMint", 112, () -> prepare(Step.CONNECT));
                    action("Use an SSID", 142, () -> prepare(Step.IMPORT));
                }
                quiet("Back", left, footer, 56, this::close);
                quiet("Settings", left + span - 70, footer, 70, () -> go(Step.SETTINGS));
                if (rt().activeId() != null)
                    quiet(
                            "Use launcher account",
                            left + span - 136,
                            12,
                            136,
                            () -> {
                                rt().restoreLauncher();
                                go(Step.HOME);
                            });
                break;
            case ADD:
                primary("Link AutoMint", 112, () -> prepare(Step.CONNECT));
                action("Use an SSID", 142, () -> prepare(Step.IMPORT));
                break;
            case CONNECT:
                if (!rt().pairingCode().isEmpty()) {
                    primary("Open AutoMint", 150, () -> rt().openPairingWebsite());
                    action("Copy link", 180, () -> rt().copyPairingWebsiteLink());
                } else primary("Try linking again", 128, () -> prepare(Step.CONNECT));
                break;
            case IMPORT:
                secret = field(900, 102, 16384);
                secret.setFocused(true);
                if (draft != null) {
                    secret.setText(new String(draft));
                    clearDraft();
                }
                if (rt().linked())
                    action(
                            "Save on AutoMint: " + (cloud ? "On" : "Off"),
                            134,
                            () -> {
                                cloud = !cloud;
                                preserveInput();
                            });
                primary(
                        "Add account",
                        rt().linked() ? 164 : 146,
                        () -> {
                            clearDraft();
                            draft = secret.getText().toCharArray();
                            String value = new String(draft);
                            secret.setText("");
                            work(
                                    Job.IMPORT,
                                    Step.IMPORT,
                                    () -> rt().importSsid(value, cloud && rt().linked()));
                        });
                break;
            case WORKING:
                if (job == Job.SELECT)
                    quiet("Cancel", left + (span - 80) / 2, footer, 80, this::back);
                break;
            case READY:
                primary("Back to Minecraft", 142, this::close);
                break;
            case ERROR:
                primary(
                        "Try again",
                        142,
                        () -> {
                            Step target = errorReturn;
                            if (preparation != null && selected != null)
                                work(Job.SELECT, Step.HOME, () -> rt().select(selected, false));
                            else if (target == Step.CONNECT) prepare(Step.CONNECT);
                            else go(target);
                        });
                break;
            case UNLOCK:
            case PASSWORD:
                secret = field(900, 106, 1024);
                secret.setFocused(true);
                if (step == Step.PASSWORD) repeat = field(901, 144, 1024);
                primary(
                        step == Step.PASSWORD ? "Create password" : "Unlock",
                        step == Step.PASSWORD ? 178 : 142,
                        () -> {
                            char[] value = secret.getText().toCharArray();
                            if (step == Step.PASSWORD) {
                                char[] other = repeat.getText().toCharArray();
                                boolean matches = Arrays.equals(value, other);
                                Arrays.fill(other, '\0');
                                if (value.length < 10 || !matches) {
                                    Arrays.fill(value, '\0');
                                    localError =
                                            value.length < 10
                                                    ? "Use at least 10 characters."
                                                    : "The passwords do not match.";
                                    return;
                                }
                            }
                            boolean create = step == Step.PASSWORD;
                            clearInput();
                            work(Job.UNLOCK, step, () -> rt().unlock(value, create));
                        });
                break;
            case RECOVERY:
                if ("VAULT_REVOKED".equals(rt().storageIssue()))
                    primary(
                            "Set up again",
                            120,
                            () -> work(Job.RESET, Step.HOME, () -> rt().resetClearedVault()));
                else {
                    primary(
                            "Retry " + rt().nativeStorageName(),
                            112,
                            () ->
                                    work(
                                            Job.STORAGE,
                                            Step.RECOVERY,
                                            () -> rt().prepareGuidedStorage()));
                    if (rt().canCreatePasswordVault())
                        action("Use a password instead", 142, () -> go(Step.PASSWORD));
                    else action("Device recovery options", 142, () -> go(Step.ADVANCED));
                }
                break;
            case SYNC:
                primary(
                        "Sync local accounts",
                        112,
                        () -> work(Job.SYNC, Step.HOME, () -> rt().syncExisting()));
                action("Keep only on this device", 142, () -> go(Step.HOME));
                break;
            case MOVE:
                primary(
                        "Move play here",
                        120,
                        () -> work(Job.SELECT, Step.HOME, () -> rt().select(selected, true)));
                action("Choose another account", 150, () -> go(Step.HOME));
                break;
            case SETTINGS:
                action(
                        "Manage accounts",
                        104,
                        () -> {
                            page = 0;
                            go(Step.MANAGE);
                        });
                action("Appearance", 132, () -> go(Step.APPEARANCE));
                action("Updates", 160, () -> go(Step.UPDATES));
                quiet(
                        "Device & security",
                        left + (span - 140) / 2,
                        190,
                        140,
                        () -> go(Step.DEVICE));
                break;
            case APPEARANCE:
                action(
                        "Mint theme: " + (rt().theme() ? "On" : "Off"),
                        116,
                        () -> {
                            rt().toggleTheme();
                            initGui();
                        });
                break;
            case UPDATES:
                action(
                        "Automatic updates: " + (rt().automaticUpdates() ? "On" : "Off"),
                        126,
                        () -> {
                            rt().toggleAutomaticUpdates();
                            initGui();
                        });
                if (rt().linked()) primary("Check for updates", 156, () -> rt().checkUpdates());
                else action("Open downloads", 156, () -> rt().openDownloadsWebsite());
                break;
            case DEVICE:
                {
                    int y = 108;
                    if (!rt().linked()) {
                        primary("Link AutoMint", y, () -> prepare(Step.CONNECT));
                        y += 30;
                    } else {
                        if (localCount() > 0) {
                            action(
                                    "Sync local accounts",
                                    y,
                                    () -> work(Job.SYNC, Step.DEVICE, () -> rt().syncExisting()));
                            y += 30;
                        }
                        action(
                                "Unlink & clear this device",
                                y,
                                () ->
                                        confirm(
                                                "Unlink and clear?",
                                                "Clears all MintAuth SSIDs on this device,"
                                                        + " including local-only entries. Cloud"
                                                        + " accounts remain saved.",
                                                () ->
                                                        work(
                                                                Job.CLEAR,
                                                                Step.DEVICE,
                                                                () -> rt().unlinkAndClear())));
                        y += 30;
                    }
                    quiet(
                            "Advanced options",
                            left + (span - 130) / 2,
                            Math.min(y, 186),
                            130,
                            () -> go(Step.ADVANCED));
                    break;
                }
            case ADVANCED:
                {
                    int y = 106;
                    action(
                            "Restore removed accounts",
                            y,
                            () -> work(Job.REFRESH, Step.ADVANCED, () -> rt().restoreHidden()));
                    y += 30;
                    if (rt().activeId() != null) {
                        action(
                                "Use launcher account",
                                y,
                                () -> {
                                    rt().restoreLauncher();
                                    go(Step.HOME);
                                });
                        y += 30;
                    }
                    action(
                            "Clear local credentials",
                            y,
                            () ->
                                    confirm(
                                            "Clear this device?",
                                            "Clears all local MintAuth credentials. Revoke server"
                                                    + " access separately in website Security.",
                                            () ->
                                                    work(
                                                            Job.CLEAR,
                                                            Step.DEVICE,
                                                            () -> rt().clearThisDevice())));
                    break;
                }
            case MANAGE:
            case CREDENTIALS:
                library(true);
                break;
            case DETAILS:
                {
                    MintAuthRuntime.AccountView a = chosen();
                    if (a == null) {
                        quiet("Choose an account", left, 120, span, () -> go(Step.MANAGE));
                        break;
                    }
                    if (!available(a) && "EXTERNAL".equals(a.kind))
                        primary("Replace SSID", 118, () -> prepare(Step.IMPORT));
                    else if (!available(a))
                        primary(
                                "Refresh accounts",
                                118,
                                () -> work(Job.REFRESH, Step.DETAILS, () -> rt().refresh()));
                    else {
                        boolean playing = a.id.equals(rt().playingAccountId());
                        primary(
                                playing
                                        ? "Currently playing"
                                        : rt().canUseMintSession(a)
                                                ? "Use Mint session"
                                                : "Use this sign-in",
                                118,
                                () -> choose(a));
                        primary.enabled = !playing && rt().canSwitchIdentity();
                    }
                    action("More actions", 150, () -> go(Step.ACCOUNT_ACTIONS));
                    if (rt().accountSources(a.uuid).size() > 1)
                        action("Saved sign-in methods", 180, () -> go(Step.CREDENTIALS));
                    break;
                }
            case ACCOUNT_ACTIONS:
                {
                    MintAuthRuntime.AccountView a = chosen();
                    if (a == null) break;
                    int y = 106;
                    if ("EXTERNAL".equals(a.kind)) {
                        action("Secure with Mint", y, () -> rt().secureOnWebsite());
                        y += 30;
                    }
                    action(
                                            a.onAutoMint
                                                    ? "Remove local copy"
                                                    : "Remove from this device",
                                            y,
                                            () ->
                                                    work(
                                                            Job.REMOVE,
                                                            Step.MANAGE,
                                                            () -> rt().remove(selected, false)))
                                    .enabled =
                            !a.onAutoMint || a.savedOnDevice || a.id.equals(rt().activeId());
                    y += 30;
                    if (a.cloud)
                        action(
                                "Delete cloud",
                                y,
                                () ->
                                        confirm(
                                                "Delete everywhere?",
                                                "Deletes this cloud library entry on all devices."
                                                        + " Copied tokens cannot be recalled.",
                                                () ->
                                                        work(
                                                                Job.REMOVE,
                                                                Step.MANAGE,
                                                                () ->
                                                                        rt().remove(
                                                                                        selected,
                                                                                        true))));
                    break;
                }
        }
        if (primary != null
                && (step == Step.IMPORT || step == Step.UNLOCK || step == Step.PASSWORD))
            primary.enabled = secret != null && !secret.getText().trim().isEmpty() && !rt().busy();
        if (step == Step.IMPORT) {
            int linkWidth = Math.min(176, span - 72);
            websiteButton =
                    button(
                                    "Secure a new account",
                                    left + span - linkWidth,
                                    footer,
                                    linkWidth,
                                    () -> {
                                        if (rt().secureWebsiteAttempted())
                                            rt().copySecureWebsiteLink();
                                        else rt().secureNewAccountOnWebsite();
                                    })
                            .quiet();
        }
        if (step != Step.HOME && step != Step.STARTING && step != Step.WORKING)
            quiet("Back", left, footer, 60, this::back);
    }

    private void completed() {
        if (job == Job.SELECT && preparation != null) {
            AccountPreparation.Snapshot result = preparation.snapshot();
            if (result.phase == AccountPreparation.Phase.APPLYING) {
                if (applyDeadline == 0) applyDeadline = System.nanoTime() + 30_000_000_000L;
                else if (System.nanoTime() > applyDeadline) {
                    rt().cancelPreparation();
                    job = Job.NONE;
                    go(Step.ERROR);
                    localError = "Minecraft did not finish switching accounts. Try again.";
                    return;
                }
            }
            if (!result.phase.terminal()) return;
            job = Job.NONE;
            switch (result.phase) {
                case READY:
                    go(Step.READY);
                    break;
                case MOVE:
                    go(Step.MOVE);
                    break;
                case CANCELLED:
                    go(Step.HOME);
                    break;
                default:
                    go(Step.ERROR);
                    localError = result.message;
            }
            return;
        }
        MintAuthRuntime.UiOperation result = rt().completedOperation(ticket);
        if (result == null) return;
        if (!result.succeeded) {
            if (rt().needsPassword()) {
                boolean failedUnlock = job == Job.UNLOCK;
                storageGate();
                if (failedUnlock && step == Step.UNLOCK)
                    localError = "That password could not unlock your accounts.";
                return;
            }
            go(Step.ERROR);
            localError = result.message;
            return;
        }
        switch (job) {
            case STORAGE:
            case UNLOCK:
            case RESET:
                job = Job.NONE;
                continueAfterStorage();
                break;
            case LINK:
                job = Job.NONE;
                go(Step.CONNECT);
                break;
            case IMPORT:
                clearDraft();
                job = Job.NONE;
                go(Step.HOME);
                break;
            default:
                job = Job.NONE;
                go(
                        errorReturn == Step.DEVICE
                                ? Step.DEVICE
                                : errorReturn == Step.MANAGE
                                        ? Step.MANAGE
                                        : errorReturn == Step.DETAILS
                                                ? Step.DETAILS
                                                : errorReturn == Step.ADVANCED
                                                        ? Step.ADVANCED
                                                        : Step.HOME);
        }
    }

    @Override
    public void updateScreen() {
        if (secret != null) secret.updateCursorCounter();
        if (repeat != null) repeat.updateCursorCounter();
        if (rt() == null) return;
        if ("VAULT_REVOKED".equals(rt().storageIssue())
                && step != Step.HOME
                && step != Step.RECOVERY
                && step != Step.STARTING
                && step != Step.ADVANCED
                && !(step == Step.WORKING && job == Job.RESET)) {
            if (job == Job.SELECT) rt().cancelPreparation();
            clearDraft();
            job = Job.NONE;
            go(Step.HOME);
            return;
        }
        if (step == Step.STARTING && rt().startupReady()) {
            go(Step.HOME);
            return;
        }
        if (step == Step.WORKING) {
            completed();
            return;
        }
        if (step == Step.CONNECT) {
            if (rt().linked()) {
                go(localCount() > 0 ? Step.SYNC : Step.HOME);
                return;
            }
            if (!rt().pairingCode().isEmpty() && !browserOpened) {
                browserOpened = true;
                rt().openPairingWebsite();
                initGui();
            }
        }
        if (primary != null
                && (step == Step.IMPORT || step == Step.UNLOCK || step == Step.PASSWORD))
            primary.enabled = secret != null && !secret.getText().trim().isEmpty() && !rt().busy();
        if (step == Step.CONNECT && primary != null)
            primary.enabled = !rt().pairingWebsiteOpening();
        if (step == Step.HOME
                || step == Step.MANAGE
                || step == Step.DETAILS
                || step == Step.CREDENTIALS
                || step == Step.DEVICE) {
            StringBuilder value =
                    new StringBuilder()
                            .append(rt().linked())
                            .append(rt().needsPassword())
                            .append(rt().storageIssue())
                            .append(rt().activeId())
                            .append(rt().playingAccountId());
            value.append(rt().playingSourceLabel());
            for (MintAuthRuntime.AccountView a : rt().accounts())
                value.append(a.id)
                        .append(a.ign)
                        .append(a.status)
                        .append(a.savedOnDevice)
                        .append(a.needsSync);
            if (!signature.equals(value.toString())) {
                signature = value.toString();
                initGui();
            }
        }
    }

    private String heading() {
        switch (step) {
            case HOME:
                if ("VAULT_REVOKED".equals(rt().storageIssue())) return "Device access ended";
                if (rt().needsPassword()) return "Your accounts are locked";
                return accounts().isEmpty()
                        ? (rt().linked() ? "No accounts yet" : "Welcome to MintAuth")
                        : "Choose an account";
            case ADD:
                return "Add an account";
            case CONNECT:
                return "Approve on AutoMint";
            case IMPORT:
                return "Add an SSID";
            case WORKING:
                return job == Job.SELECT
                        ? "Getting your account ready"
                        : job == Job.IMPORT ? "Saving your account" : "One moment";
            case READY:
                return rt().multiplayerIssue() == null ? "You're ready" : "Singleplayer is ready";
            case ERROR:
                return "Couldn't finish this step";
            case UNLOCK:
                return "Unlock your accounts";
            case PASSWORD:
                return "Protect your accounts";
            case RECOVERY:
                return "Storage needs attention";
            case SYNC:
                return "Keep accounts in sync?";
            case MOVE:
                return "Already playing elsewhere";
            case SETTINGS:
                return "Settings";
            case APPEARANCE:
                return "Appearance";
            case UPDATES:
                return "Updates";
            case DEVICE:
                return "Device & security";
            case ADVANCED:
                return "Advanced options";
            case MANAGE:
                return "Manage accounts";
            case CREDENTIALS:
                return "Saved sign-in methods";
            case DETAILS:
            case ACCOUNT_ACTIONS:
                return chosen() == null ? "Account unavailable" : chosen().ign;
            default:
                return "Starting MintAuth";
        }
    }

    private String description() {
        switch (step) {
            case HOME:
                if ("VAULT_REVOKED".equals(rt().storageIssue()))
                    return "MintAuth credentials were cleared on this device.";
                if (rt().needsPassword()) return "Unlock saved accounts to continue.";
                return accounts().isEmpty()
                        ? (rt().linked()
                                ? "Refresh your Mint library, or add an SSID."
                                : "How would you like to sign in?")
                        : "Select an account to play. You can switch later.";
            case ADD:
                return "Choose where your account comes from.";
            case CONNECT:
                return rt().pairingCode().isEmpty()
                        ? rt().status()
                        : rt().pairingWebsiteNotice() != null
                                ? rt().pairingWebsiteNotice()
                                : "Approve the request in your browser. We'll continue here"
                                        + " automatically.";
            case IMPORT:
                return rt().secureWebsiteNotice() != null
                        ? rt().secureWebsiteNotice()
                        : "Paste a Minecraft SSID. The token stays hidden.";
            case WORKING:
                if (job == Job.SELECT && preparation != null) return preparation.snapshot().message;
                if (job == Job.REFRESH) return "Refreshing your AutoMint account list...";
                if (job == Job.REMOVE) return "Removing the saved account copy...";
                return job == Job.STORAGE
                        ? "Opening secure storage..."
                        : job == Job.IMPORT
                                ? "Checking the SSID and saving it securely..."
                                : rt().status();
            case READY:
                if (rt().multiplayerIssue() != null) return rt().multiplayerIssue();
                return "Signed in as "
                        + (rt().activeIgn() == null ? "your launcher account" : rt().activeIgn())
                        + ".";
            case ERROR:
                return localError == null ? rt().status() : localError;
            case UNLOCK:
                return "Enter your MintAuth storage password.";
            case PASSWORD:
                return "Choose a password of at least 10 characters to protect your saved"
                        + " accounts.";
            case RECOVERY:
                return rt().storageRecoveryDescription();
            case SYNC:
                return "Your existing local accounts stay on this device unless you choose to sync"
                        + " them.";
            case MOVE:
                return "Moving play will ask the other local Minecraft instance to release this"
                        + " account.";
            case SETTINGS:
                return "Choose what you want to change.";
            case APPEARANCE:
                return "Mint styling is optional. Your game HUD stays unchanged.";
            case UPDATES:
                return "Signed updates install after Minecraft closes.";
            case DEVICE:
                return rt().linked()
                        ? "This device is linked to AutoMint."
                        : "You're using MintAuth without a website link.";
            case ADVANCED:
                return "Recovery and credential removal for this device.";
            case MANAGE:
                return accounts().isEmpty()
                        ? "Add an account from the main screen first."
                        : "Choose an account to manage.";
            case CREDENTIALS:
                return "Mint is preferred for Play. Other sign-ins stay separate.";
            case DETAILS:
            case ACCOUNT_ACTIONS:
                MintAuthRuntime.AccountView a = chosen();
                return a == null
                        ? "Refresh the library to check availability."
                        : a.label() + " - " + (a.status == null ? "Available" : a.status);
            default:
                return "Checking saved account state...";
        }
    }

    private void paragraph(String value, int y, int color, int lines) {
        List<String> wrapped = fontRendererObj.listFormattedStringToWidth(value, span);
        for (int i = 0; i < Math.min(lines, wrapped.size()); i++) {
            String line = wrapped.get(i);
            if (i == lines - 1 && wrapped.size() > lines)
                line = fontRendererObj.trimStringToWidth(line, span - 18) + "...";
            fontRendererObj.drawString(line, left, y + i * 11, color);
        }
    }

    private void brand() {
        if (logo == null)
            try (InputStream input =
                    MintAuthGui.class.getResourceAsStream(
                            "/assets/mintauth/textures/gui/mint-logo.png")) {
                if (input != null)
                    logo =
                            mc.getTextureManager()
                                    .getDynamicTextureLocation(
                                            "mintauth_guided",
                                            new DynamicTexture(ImageIO.read(input)));
            } catch (IOException ignored) {
            }
        if (logo != null) {
            GlStateManager.color(1, 1, 1, 1);
            mc.getTextureManager().bindTexture(logo);
            Gui.drawScaledCustomSizeModalRect(left, 12, 0, 0, 540, 540, 20, 20, 540, 540);
        }
        fontRendererObj.drawString("MintAuth", left + 28, 18, 0xffdfffe9);
    }

    @Override
    public void drawScreen(int mouseX, int mouseY, float delta) {
        if (websiteButton != null) {
            websiteButton.enabled = !rt().secureWebsiteOpening();
            websiteButton.displayString =
                    rt().secureWebsiteAttempted() ? "Copy website link" : "Secure a new account";
        }
        boolean mint = rt() == null || rt().theme();
        drawDefaultBackground();
        drawRect(0, 0, width, height, mint ? 0xf20a1510 : 0xf2101010);
        brand();
        String title = heading();
        int scale = fontRendererObj.getStringWidth(title) * 2 <= span ? 2 : 1;
        GlStateManager.pushMatrix();
        GlStateManager.translate(width / 2f, 49, 0);
        GlStateManager.scale(scale, scale, 1);
        fontRendererObj.drawString(
                title, -fontRendererObj.getStringWidth(title) / 2, 0, 0xffedf5ee);
        GlStateManager.popMatrix();
        paragraph(
                description(),
                76,
                0xffadc4b5,
                step == Step.WORKING || step == Step.ERROR || step == Step.RECOVERY ? 4 : 2);
        if (step == Step.CONNECT && !rt().pairingCode().isEmpty()) {
            drawRect(left, 108, left + span, 138, 0xff183c28);
            drawCenteredString(fontRendererObj, rt().pairingCode(), width / 2, 119, 0xffbfffd8);
        }
        if (step == Step.IMPORT && !rt().linked())
            paragraph("Saved only on this device.", 132, 0xff859d8d, 1);
        if (step == Step.PASSWORD)
            fontRendererObj.drawString("Confirm password", left, 132, 0xffadc4b5);
        if (step == Step.UPDATES)
            paragraph(
                    rt().linked()
                            ? rt().updateStatus()
                            : "Link AutoMint for automatic updates, or download manually.",
                    100,
                    0xffadc4b5,
                    2);
        if (step == Step.READY)
            paragraph(
                    preparation == null ? rt().status() : preparation.snapshot().message,
                    108,
                    0xffadc4b5,
                    2);
        if (localError != null && step != Step.ERROR)
            paragraph(localError, step == Step.PASSWORD ? 168 : 180, 0xffffb9ae, 1);
        if (step == Step.WORKING || step == Step.STARTING)
            MintLoadingAnimation.draw(
                    Gui::drawRect,
                    width / 2,
                    124,
                    span,
                    Math.max(0, footer - 132),
                    (System.nanoTime() - animationStarted) / 1_000_000L,
                    mint);
        if ((step == Step.HOME || step == Step.MANAGE || step == Step.CREDENTIALS)
                && !accounts().isEmpty()) {
            List<MintAuthRuntime.AccountView> displayed =
                    step == Step.CREDENTIALS && chosen() != null
                            ? rt().accountSources(chosen().uuid)
                            : accounts();
            int rows = Math.max(1, (height - 152) / (step == Step.CREDENTIALS ? 28 : 48));
            if (displayed.size() > rows)
                drawCenteredString(
                        fontRendererObj,
                        (page + 1) + " / " + ((displayed.size() + rows - 1) / rows),
                        width / 2,
                        height - 51,
                        0xffadc4b5);
        }
        if (secret != null) secret.drawTextBox();
        if (repeat != null) repeat.drawTextBox();
        super.drawScreen(mouseX, mouseY, delta);
        for (GuiButton item : buttonList)
            if (item instanceof MintButton
                    && ((MintButton) item).needsTooltip(mc, mouseX, mouseY)) {
                drawHoveringText(Collections.singletonList(item.displayString), mouseX, mouseY);
                break;
            }
    }

    @Override
    protected void actionPerformed(GuiButton b) {
        Runnable action = actions.get(b.id);
        if (action != null) action.run();
    }

    @Override
    protected void mouseClicked(int x, int y, int button) throws IOException {
        focus = -1;
        for (GuiButton b : buttonList)
            if (b instanceof MintButton) ((MintButton) b).keyboardFocused(false);
        Step before = step;
        SecretField oldSecret = secret, oldRepeat = repeat;
        super.mouseClicked(x, y, button);
        if (step == before && secret != null && secret == oldSecret)
            secret.mouseClicked(x, y, button);
        if (step == before && repeat != null && repeat == oldRepeat)
            repeat.mouseClicked(x, y, button);
    }

    @Override
    protected void keyTyped(char c, int key) throws IOException {
        if (key == Keyboard.KEY_ESCAPE) {
            back();
            return;
        }
        if (key == Keyboard.KEY_TAB) {
            List<Integer> enabled = new ArrayList<>();
            for (int i = 0; i < buttonList.size(); i++)
                if (buttonList.get(i).enabled) enabled.add(i);
            int fields = secret == null ? 0 : repeat == null ? 1 : 2,
                    total = fields + enabled.size();
            if (total == 0) return;
            int current =
                    secret != null && secret.isFocused()
                            ? 0
                            : repeat != null && repeat.isFocused()
                                    ? 1
                                    : focus >= 0 && enabled.contains(focus)
                                            ? fields + enabled.indexOf(focus)
                                            : -1;
            int direction =
                    Keyboard.isKeyDown(Keyboard.KEY_LSHIFT)
                                    || Keyboard.isKeyDown(Keyboard.KEY_RSHIFT)
                            ? -1
                            : 1;
            if (current < 0) current = direction > 0 ? -1 : 0;
            int target = (current + direction + total) % total;
            if (secret != null) secret.setFocused(target == 0);
            if (repeat != null) repeat.setFocused(target == 1);
            focus = target < fields ? -1 : enabled.get(target - fields);
            for (int i = 0; i < buttonList.size(); i++)
                if (buttonList.get(i) instanceof MintButton)
                    ((MintButton) buttonList.get(i)).keyboardFocused(i == focus);
            return;
        }
        if (key == Keyboard.KEY_RETURN || key == Keyboard.KEY_NUMPADENTER) {
            GuiButton b = focus >= 0 && focus < buttonList.size() ? buttonList.get(focus) : primary;
            if (b != null && b.enabled) actionPerformed(b);
            return;
        }
        if (secret != null && secret.textboxKeyTyped(c, key)) return;
        if (repeat != null && repeat.textboxKeyTyped(c, key)) return;
        super.keyTyped(c, key);
    }

    @Override
    public void onGuiClosed() {
        if (rt() != null) rt().dismissWelcome();
        clearInput();
        clearDraft();
        Keyboard.enableRepeatEvents(false);
    }

    @Override
    public boolean doesGuiPauseGame() {
        return false;
    }

    private static final class SecretField extends GuiTextField {
        SecretField(
                int id, net.minecraft.client.gui.FontRenderer font, int x, int y, int w, int h) {
            super(id, font, x, y, w, h);
        }

        @Override
        public void drawTextBox() {
            String raw = getText();
            int cursor = getCursorPosition(), selection = getSelectionEnd();
            char[] mask = new char[raw.length()];
            Arrays.fill(mask, '*');
            setText(new String(mask));
            setCursorPosition(cursor);
            setSelectionPos(selection);
            super.drawTextBox();
            setText(raw);
            setCursorPosition(cursor);
            setSelectionPos(selection);
        }
    }
}
