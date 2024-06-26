package org.bouncycastle.crypto.agreement.owl;

import org.bouncycastle.crypto.CryptoException;

public class OwlAuthenticationFailure extends CryptoException {
    public OwlAuthenticationFailure(String message) {
        super(message);
    }
}
