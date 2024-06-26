package org.bouncycastle.crypto.agreement.owl.messages;

import org.bouncycastle.crypto.agreement.owl.OwlZKP;
import org.bouncycastle.math.ec.ECPoint;

public class InitialLoginRequest {
    private ECPoint X1;
    private ECPoint X2;
    private OwlZKP PI1;
    private OwlZKP PI2;

    public InitialLoginRequest(ECPoint X1, ECPoint X2, OwlZKP PI1, OwlZKP PI2) {
        this.X1 = X1;
        this.X2 = X2;
        this.PI1 = PI1;
        this.PI2 = PI2;
    }

    public ECPoint getX1() {
        return X1;
    }

    public ECPoint getX2() {
        return X2;
    }

    public OwlZKP getPI1() {
        return PI1;
    }

    public OwlZKP getPI2() {
        return PI2;
    }
}
