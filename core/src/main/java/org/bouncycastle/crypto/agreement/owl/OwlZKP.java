package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

public class OwlZKP {
    protected BigInteger h;
    protected BigInteger r;

    public OwlZKP(BigInteger h, BigInteger r) {
        this.h = h;
        this.r = r;
    }

    public BigInteger getH() {
        return this.h;
    }

    public BigInteger getR() {
        return this.r;
    }
}
