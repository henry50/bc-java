package org.bouncycastle.crypto.agreement.owl;

import org.bouncycastle.crypto.CryptoException;

public class OwlZKPVerificationFailure extends CryptoException {
    public OwlZKPVerificationFailure(String message) {
        super(message);
    }
}
