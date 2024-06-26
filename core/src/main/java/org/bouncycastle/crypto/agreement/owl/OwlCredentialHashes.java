package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

public class OwlCredentialHashes {
    private BigInteger t;
    private BigInteger pi;
    public OwlCredentialHashes(BigInteger t, BigInteger pi) {
        this.t = t;
        this.pi = pi;
    }
    public BigInteger getT() {
        return t;
    }
    public BigInteger getPi() {
        return pi;
    }
}
