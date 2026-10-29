// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Test;

import java.awt.HeadlessException;
import java.net.URI;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicReference;

public class AccountWebsiteActionTest {
    @Test
    public void browserDispatchIsAsynchronousAndUsesOnlyTheFixedPublicLink() {
        Queue<Runnable> pending = new ArrayDeque<>();
        AtomicReference<URI> opened = new AtomicReference<>();
        AccountWebsiteAction action = new AccountWebsiteAction(pending::add, opened::set);
        action.open();
        action.open();
        assertTrue(action.opening());
        assertNull(opened.get());
        assertEquals(1, pending.size());
        pending.remove().run();
        assertEquals(
                "https://automint.online/dashboard/accounts?action=add", opened.get().toString());
        assertNull(opened.get().getUserInfo());
        assertNull(opened.get().getFragment());
        assertFalse(action.opening());
        assertTrue(action.attempted());
        assertTrue(action.message().contains("browser"));
    }

    @Test
    public void headlessFailureBecomesVisibleRecoveryWithoutLeakingTheException() {
        AccountWebsiteAction action =
                new AccountWebsiteAction(
                        Runnable::run,
                        url -> {
                            throw new HeadlessException("SYNTHETIC_SECRET_SENTINEL");
                        });
        action.open();
        assertFalse(action.opening());
        assertTrue(action.attempted());
        assertTrue(action.message().contains("Copy website link"));
        assertFalse(action.message().contains("SYNTHETIC_SECRET_SENTINEL"));
        action.copied(true);
        assertTrue(action.message().contains("copied"));
        action.copied(false);
        assertTrue(action.message().contains("automint.online/dashboard/accounts?action=add"));
    }

    @Test
    public void leavingTheFlowCancelsAnUnstartedBrowserAction() {
        Queue<Runnable> pending = new ArrayDeque<>();
        AtomicReference<URI> opened = new AtomicReference<>();
        AccountWebsiteAction action = new AccountWebsiteAction(pending::add, opened::set);
        action.open();
        action.clear();
        pending.remove().run();
        assertNull(opened.get());
        assertNull(action.message());
        assertFalse(action.opening());
        assertFalse(action.attempted());
    }

    @Test
    public void lateFailureCannotReplaceTheNewerBrowserResult() {
        Queue<Runnable> pending = new ArrayDeque<>();
        AccountWebsiteAction[] holder = new AccountWebsiteAction[1];
        holder[0] =
                new AccountWebsiteAction(
                        pending::add,
                        url -> {
                            holder[0].clear();
                            holder[0].open();
                            throw new HeadlessException("OLD_ATTEMPT");
                        });
        holder[0].open();
        pending.remove().run();
        assertTrue(holder[0].opening());
        assertFalse(holder[0].attempted());
        assertTrue(holder[0].message().startsWith("Opening"));
    }
}
