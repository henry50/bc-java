package org.bouncycastle.crypto.agreement.owl.messages;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class RegisterRequest {
    private BigInteger t;
    private BigInteger pi;
    private ECPoint T;

    public RegisterRequest(BigInteger t, BigInteger pi, ECPoint T) {
        this.t = t;
        this.pi = pi;
        this.T = T;
    }

    public BigInteger gett() {
        return this.t;
    }

    public BigInteger getPi() {
        return this.pi;
    }

    public ECPoint getT() {
        return this.T;
    }
}
