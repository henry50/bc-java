package org.bouncycastle.crypto.agreement.owl.messages;

import org.bouncycastle.crypto.agreement.owl.OwlZKP;
import org.bouncycastle.math.ec.ECPoint;

public class InitialLoginResponse {
    private ECPoint X3;
    private ECPoint X4;
    private OwlZKP PI3;
    private OwlZKP PI4;
    private ECPoint beta;
    private OwlZKP PIbeta;

    public InitialLoginResponse(ECPoint X3, ECPoint X4, OwlZKP PI3, OwlZKP PI4, ECPoint beta, OwlZKP PIbeta) {
        this.X3 = X3;
        this.X4 = X4;
        this.PI3 = PI3;
        this.PI4 = PI4;
        this.beta = beta;
        this.PIbeta = PIbeta;
    }

    public ECPoint getX3() {
        return X3;
    }

    public ECPoint getX4() {
        return X4;
    }

    public OwlZKP getPI3() {
        return PI3;
    }

    public OwlZKP getPI4() {
        return PI4;
    }

    public ECPoint getBeta() {
        return beta;
    }

    public OwlZKP getPIbeta() {
        return PIbeta;
    }
}
