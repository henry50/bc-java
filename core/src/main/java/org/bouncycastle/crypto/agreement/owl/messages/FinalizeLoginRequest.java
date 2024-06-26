package org.bouncycastle.crypto.agreement.owl.messages;

import java.math.BigInteger;

import org.bouncycastle.crypto.agreement.owl.OwlZKP;
import org.bouncycastle.math.ec.ECPoint;

public class FinalizeLoginRequest {
    private ECPoint alpha;
    private OwlZKP PIalpha;
    private BigInteger r;

    public FinalizeLoginRequest(ECPoint alpha, OwlZKP PIalpha, BigInteger r) {
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
