// Copyright (c) 2026 AutoMint. License: see LICENSE.
package online.automint.mintauth.core;

public interface SecretStore {
    String name();

    byte[] read(String generation) throws Exception;

    void write(String generation, byte[] secret) throws Exception;

    void remove(String generation) throws Exception;
}
