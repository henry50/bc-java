package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class OwlClientRegisterMessage {
    private BigInteger t;
    private BigInteger pi;
    private ECPoint T;
    public OwlClientRegisterMessage(BigInteger t, BigInteger pi, ECPoint T)
    {
        this.t = t;
        this.pi = pi;
        this.T = T;
    }
    public BigInteger gett()
    {
        return this.t;
    }
    public BigInteger getPi()
    {
        return this.pi;
    }
    public ECPoint getT()
    {
        return this.T;
    }
}
