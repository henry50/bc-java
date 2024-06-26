package org.bouncycastle.crypto.agreement.owl;

import org.bouncycastle.crypto.agreement.owl.messages.FinalizeLoginRequest;

/**
 * Contains the derived key and finalize login request produced by
 * OwlClient.finalizeLogin
 */
public class OwlClientFinalValues {
    private byte[] key;
    private FinalizeLoginRequest finalizeLoginRequest;

    public OwlClientFinalValues(byte[] key, FinalizeLoginRequest finalizeLoginRequest) {
        this.key = key;
        this.finalizeLoginRequest = finalizeLoginRequest;
    }

    public byte[] getKey() {
        return key;
    }

    public FinalizeLoginRequest getFinalizeLoginRequest() {
        return finalizeLoginRequest;
    }
}
