package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class OwlUserCredentials {
    ECPoint X3;
    OwlZKP PI3;
    BigInteger pi;
    ECPoint T;

    public OwlUserCredentials(ECPoint X3, OwlZKP PI3, BigInteger pi, ECPoint T) {
        this.X3 = X3;
        this.PI3 = PI3;
        this.pi = pi;
        this.T = T;
    }

    public ECPoint getX3() {
        return X3;
    }

    public OwlZKP getPI3() {
        return PI3;
    }

    public BigInteger getPi() {
        return pi;
    }

    public ECPoint getT() {
        return T;
    }
}
