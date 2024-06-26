package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;

import org.bouncycastle.math.ec.ECPoint;

public class OwlClientFinalizeLoginMessage {
    private ECPoint alpha;
    private OwlZKP PIalpha;
    private BigInteger r;
    public OwlClientFinalizeLoginMessage(ECPoint alpha, OwlZKP PIalpha, BigInteger r) {
        this.alpha = alpha;
        this.PIalpha = PIalpha;
        this.r = r;
    }
    public ECPoint getAlpha() {
        return alpha;
    }
    public OwlZKP getPIalpha() {
        return PIalpha;
    }
    public BigInteger getR() {
        return r;
    }
}
