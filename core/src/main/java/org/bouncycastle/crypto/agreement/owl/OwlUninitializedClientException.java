package org.bouncycastle.crypto.agreement.owl;

import org.bouncycastle.crypto.CryptoException;

public class OwlUninitializedClientException extends CryptoException {
    public OwlUninitializedClientException(String message) {
        super(message);
    }
}
