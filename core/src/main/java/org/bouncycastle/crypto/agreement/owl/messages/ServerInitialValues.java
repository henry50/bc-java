package org.bouncycastle.crypto.agreement.owl.messages;

import java.math.BigInteger;

import org.bouncycastle.crypto.agreement.owl.OwlZKP;
import org.bouncycastle.math.ec.ECPoint;

public class ServerInitialValues {
    private ECPoint T;
    private BigInteger pi;
    private BigInteger x4;
    private ECPoint X1;
    private ECPoint X2;
    private ECPoint X3;
    private ECPoint X4;
    private ECPoint beta;
    private OwlZKP PI1;
    private OwlZKP PI2;
    private OwlZKP PI3;
    private OwlZKP PI4;
    private OwlZKP PIbeta;

    public ServerInitialValues(ECPoint T, BigInteger pi, BigInteger x4, ECPoint X1, ECPoint X2, ECPoint X3, ECPoint X4,
            ECPoint beta, OwlZKP PI1, OwlZKP PI2, OwlZKP PI3, OwlZKP PI4, OwlZKP PIbeta) {
        this.T = T;
        this.pi = pi;
        this.x4 = x4;
        this.X1 = X1;
        this.X2 = X2;
        this.X3 = X3;
        this.X4 = X4;
        this.beta = beta;
        this.PI1 = PI1;
        this.PI2 = PI2;
        this.PI3 = PI3;
        this.PI4 = PI4;
        this.PIbeta = PIbeta;
    }

    public ECPoint getT() {
        return T;
    }

    public BigInteger getPi() {
        return pi;
    }

    public BigInteger getx4() {
        return x4;
    }

    public ECPoint getX1() {
        return X1;
    }

    public ECPoint getX2() {
        return X2;
    }

    public ECPoint getX3() {
        return X3;
    }

    public ECPoint getX4() {
        return X4;
    }

    public ECPoint getBeta() {
        return beta;
    }

    public OwlZKP getPI1() {
        return PI1;
    }

    public OwlZKP getPI2() {
        return PI2;
    }

    public OwlZKP getPI3() {
        return PI3;
    }

    public OwlZKP getPI4() {
        return PI4;
    }

    public OwlZKP getPIbeta() {
        return PIbeta;
    }
}
