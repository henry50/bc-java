package org.bouncycastle.crypto.agreement.owl;

public class OwlClientFinalValues {
    public byte[] key;
    public OwlClientFinalizeLoginMessage finalizeLoginMessage;
    public OwlClientFinalValues(byte[] key, OwlClientFinalizeLoginMessage finalizeLoginMessage) {
        this.key = key;
        this.finalizeLoginMessage = finalizeLoginMessage;
    }
}
