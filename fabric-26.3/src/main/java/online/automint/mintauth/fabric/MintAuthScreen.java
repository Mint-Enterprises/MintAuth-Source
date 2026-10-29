// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.fabric;

import net.minecraft.client.gui.GuiGraphicsExtractor;
import net.minecraft.client.gui.components.EditBox;
import net.minecraft.client.gui.screens.ConfirmScreen;
import net.minecraft.client.gui.screens.Screen;
import net.minecraft.client.input.KeyEvent;
import net.minecraft.client.renderer.RenderPipelines;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.network.chat.Style;
import net.minecraft.resources.Identifier;
import net.minecraft.util.FormattedCharSequence;

import online.automint.mintauth.core.AccountPreparation;
import online.automint.mintauth.core.MintAuthRuntime;
import online.automint.mintauth.core.MintLoadingAnimation;

import java.util.*;

public final class MintAuthScreen extends Screen {
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

    private final Screen parent;
    private Step step = Step.STARTING, resume = Step.HOME, errorReturn = Step.HOME;
    private Job job = Job.NONE;
    private String selected, signature = "", localError;
    private SecretBox secret, repeat;
    private char[] draft;
    private MintButton primary, websiteButton;
    private boolean cloud = true, browserOpened;
    private int page, left, span, footer;
    private long ticket, applyDeadline;
    private AccountPreparation preparation;
    private long animationStarted = System.nanoTime();
    private static final Identifier LOGO =
            Identifier.fromNamespaceAndPath("mintauth", "textures/gui/mint-logo.png");

    public MintAuthScreen(Screen parent) {
        super(Component.literal("MintAuth"));
        this.parent = parent;
        if (rt() != null) rt().logUiStep(step.name());
    }

    private MintAuthRuntime rt() {
        return MintAuthClient.runtime();
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
        return addRenderableWidget(new MintButton(label, x, y, w, 22, tracedAction(action)));
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
        if (secret != null) secret.setValue("");
        if (repeat != null) repeat.setValue("");
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
        rebuildWidgets();
    }

    private void preserveInput() {
        String value = secret == null ? null : secret.getValue();
        rebuildWidgets();
        if (secret != null && value != null) secret.setValue(value);
    }

    private void closeFlow() {
        if (job == Job.SELECT) rt().cancelPreparation();
        clearInput();
        clearDraft();
        if (rt() != null) rt().dismissWelcome();
        minecraft.gui.setScreen(parent);
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
                closeFlow();
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
            row.active = manage || !playing;
            if (!sources && playing && rt().canUseMintSession(a))
                button(
                                        "Use Mint session",
                                        left + span - 136,
                                        122 + (i - page * rows) * spacing,
                                        136,
                                        () -> choose(a))
                                .quiet()
                                .active =
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
                                        rebuildWidgets();
                                    })
                            .active =
                    page > 0;
            button(
                                    ">",
                                    left + span - 32,
                                    y,
                                    32,
                                    () -> {
                                        page++;
                                        rebuildWidgets();
                                    })
                            .active =
                    (page + 1) * rows < all.size();
        }
    }

    private SecretBox field(int id, int y, int maximum) {
        SecretBox f =
                addRenderableWidget(
                        new SecretBox(
                                font,
                                left,
                                y,
                                span,
                                20,
                                Component.literal(
                                        id == 901
                                                ? "Confirm password"
                                                : step == Step.IMPORT
                                                        ? "Minecraft SSID"
                                                        : "Storage password")));
        f.setMaxLength(maximum);
        return f;
    }

    private void confirm(String title, String text, Runnable action) {
        minecraft.gui.setScreen(
                new ConfirmScreen(
                        yes -> {
                            minecraft.gui.setScreen(this);
                            if (yes) action.run();
                        },
                        Component.literal(title),
                        Component.literal(text)));
    }

    @Override
    protected void init() {
        String saved = secret == null ? null : secret.getValue();
        String savedRepeat = repeat == null ? null : repeat.getValue();
        clearInput();
        primary = null;
        websiteButton = null;
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
                quiet("Back", left, footer, 56, this::closeFlow);
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
                    secret.setValue(new String(draft));
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
                            draft = secret.getValue().toCharArray();
                            String value = new String(draft);
                            secret.setValue("");
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
                primary("Back to Minecraft", 142, this::closeFlow);
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
                            char[] value = secret.getValue().toCharArray();
                            if (step == Step.PASSWORD) {
                                char[] other = repeat.getValue().toCharArray();
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
                            rebuildWidgets();
                        });
                break;
            case UPDATES:
                action(
                        "Automatic updates: " + (rt().automaticUpdates() ? "On" : "Off"),
                        126,
                        () -> {
                            rt().toggleAutomaticUpdates();
                            rebuildWidgets();
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
                        primary.active = !playing && rt().canSwitchIdentity();
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
                                    .active =
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
            primary.active = secret != null && !secret.getValue().trim().isEmpty() && !rt().busy();
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
        if (saved != null && secret != null) secret.setValue(saved);
        if (savedRepeat != null && repeat != null) repeat.setValue(savedRepeat);
        updatePrimary();
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
    public void tick() {
        super.tick();
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
                rebuildWidgets();
            }
        }
        if (primary != null
                && (step == Step.IMPORT || step == Step.UNLOCK || step == Step.PASSWORD))
            primary.active = secret != null && !secret.getValue().trim().isEmpty() && !rt().busy();
        if (step == Step.CONNECT && primary != null) primary.active = !rt().pairingWebsiteOpening();
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
                rebuildWidgets();
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

    private void updatePrimary() {
        if (primary != null
                && (step == Step.IMPORT || step == Step.UNLOCK || step == Step.PASSWORD))
            primary.active = secret != null && !secret.getValue().trim().isEmpty() && !rt().busy();
    }

    @Override
    protected void setInitialFocus() {
        if (secret != null) setInitialFocus(secret);
        else super.setInitialFocus();
    }

    @Override
    public boolean keyPressed(KeyEvent event) {
        if (event.key() == 256) {
            back();
            return true;
        }
        if ((event.key() == 257 || event.key() == 335)
                && (secret != null && secret.isFocused() || repeat != null && repeat.isFocused())) {
            updatePrimary();
            if (primary != null && primary.active) primary.onPress(event);
            return true;
        }
        return super.keyPressed(event);
    }

    private void paragraph(GuiGraphicsExtractor g, String value, int y, int color, int lines) {
        List<FormattedCharSequence> wrapped = font.split(Component.literal(value), span);
        for (int i = 0; i < Math.min(lines, wrapped.size()); i++)
            g.text(font, wrapped.get(i), left, y + i * 11, color, false);
    }

    private void centered(GuiGraphicsExtractor g, String value, int y, int color) {
        g.text(font, value, (width - font.width(value)) / 2, y, color, false);
    }

    @Override
    public void extractRenderState(GuiGraphicsExtractor g, int mouseX, int mouseY, float delta) {
        if (websiteButton != null) {
            websiteButton.active = !rt().secureWebsiteOpening();
            websiteButton.setMessage(
                    Component.literal(
                            rt().secureWebsiteAttempted()
                                    ? "Copy website link"
                                    : "Secure a new account"));
        }
        boolean mint = rt() == null || rt().theme();
        g.fill(0, 0, width, height, mint ? 0xf20a1510 : 0xf2101010);
        g.blit(RenderPipelines.GUI_TEXTURED, LOGO, left, 12, 0F, 0F, 20, 20, 540, 540, 540, 540);
        g.text(font, "MintAuth", left + 28, 18, 0xffdfffe9, false);
        String heading = heading();
        int scale = font.width(heading) * 2 <= span ? 2 : 1;
        g.pose().pushMatrix();
        g.pose().translate(width / 2f, 49);
        g.pose().scale(scale, scale);
        g.text(font, heading, -font.width(heading) / 2, 0, 0xffedf5ee, false);
        g.pose().popMatrix();
        paragraph(
                g,
                description(),
                76,
                0xffadc4b5,
                step == Step.WORKING || step == Step.ERROR || step == Step.RECOVERY ? 4 : 2);
        if (step == Step.CONNECT && !rt().pairingCode().isEmpty()) {
            g.fill(left, 108, left + span, 138, 0xff183c28);
            centered(g, rt().pairingCode(), 119, 0xffbfffd8);
        }
        if (step == Step.IMPORT && !rt().linked())
            paragraph(g, "Saved only on this device.", 132, 0xff859d8d, 1);
        if (step == Step.PASSWORD) g.text(font, "Confirm password", left, 132, 0xffadc4b5, false);
        if (step == Step.UPDATES)
            paragraph(
                    g,
                    rt().linked()
                            ? rt().updateStatus()
                            : "Link AutoMint for automatic updates, or download manually.",
                    100,
                    0xffadc4b5,
                    2);
        if (step == Step.READY)
            paragraph(
                    g,
                    preparation == null ? rt().status() : preparation.snapshot().message,
                    108,
                    0xffadc4b5,
                    2);
        if (localError != null && step != Step.ERROR)
            paragraph(g, localError, step == Step.PASSWORD ? 168 : 180, 0xffffb9ae, 1);
        if (step == Step.WORKING || step == Step.STARTING)
            MintLoadingAnimation.draw(
                    g::fill,
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
                centered(
                        g,
                        (page + 1) + " / " + ((displayed.size() + rows - 1) / rows),
                        height - 51,
                        0xffadc4b5);
        }
        super.extractRenderState(g, mouseX, mouseY, delta);
    }

    @Override
    public void onClose() {
        back();
    }

    @Override
    public void removed() {
        if (rt() != null) rt().dismissWelcome();
        clearInput();
        clearDraft();
    }

    @Override
    public boolean isPauseScreen() {
        return false;
    }

    private static final class SecretBox extends EditBox {
        SecretBox(
                net.minecraft.client.gui.Font font,
                int x,
                int y,
                int width,
                int height,
                Component label) {
            super(font, x, y, width, height, label);
            addFormatter(
                    (value, offset) ->
                            FormattedCharSequence.forward("*".repeat(value.length()), Style.EMPTY));
        }

        @Override
        protected MutableComponent createNarrationMessage() {
            return Component.literal("Hidden credential input");
        }
    }
}
