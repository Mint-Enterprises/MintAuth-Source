// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

import static org.junit.Assert.*;

import org.junit.Test;

public class GuidedOperationTest {
    @Test
    public void unrelatedSuccessCannotReplaceTheRequestedFailure() {
        MintAuthRuntime.UiOperations operations = new MintAuthRuntime.UiOperations();
        operations.finish(1, false);
        operations.finish(2, true);
        assertFalse(operations.get(1).succeeded);
        assertTrue(operations.get(2).succeeded);
        assertNull(operations.get(3));
    }

    @Test
    public void lateCompletionHasItsOwnOutcome() {
        MintAuthRuntime.UiOperations operations = new MintAuthRuntime.UiOperations();
        operations.finish(2, false);
        operations.finish(1, true);
        assertTrue(operations.get(1).succeeded);
        assertFalse(operations.get(2).succeeded);
    }

    @Test
    public void completedProgressHistoryIsBounded() {
        MintAuthRuntime.UiOperations operations = new MintAuthRuntime.UiOperations();
        for (long id = 1; id <= 100; id++) operations.finish(id, true);
        assertNull(operations.get(1));
        assertNull(operations.get(36));
        assertEquals(37, operations.get(37).id);
        assertEquals(100, operations.get(100).id);
    }
}
