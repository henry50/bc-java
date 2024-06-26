package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;

public class OwlUtil {
    BigInteger n;
    Digest digest;
    SecureRandom random;
    public OwlUtil(BigInteger n, Digest digest, SecureRandom random){
        this.n = n;
        this.digest = digest;
        this.random = random;
    }
    public OwlZKP createZKP(BigInteger x, ECPoint X, ECPoint G, byte[] identity)
    {
        BigInteger v = getRandomInCurve();
        ECPoint V = G.multiply(v);
        byte[] Gb = G.getEncoded(true);
        byte[] Vb = V.getEncoded(true);
        byte[] Xb = X.getEncoded(true);
        digest.update(Gb, 0, Gb.length);
        digest.update(Vb, 0, Vb.length);
        digest.update(Xb, 0, Xb.length);
        digest.update(identity, 0, identity.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        BigInteger h = new BigInteger(1, output);

        BigInteger r = v.subtract(x.multiply(h)).mod(n);
        return new OwlZKP(h, r);
    }
    public boolean verifyZKP(OwlZKP zkp, ECPoint G, ECPoint X, BigInteger q, byte[] proverIdentity)
    {
        // Check X != infinity
        if (X.isInfinity()) {
            return false;
        }
        // Check x and y coordinates are in Fq
        if (X.normalize().getXCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
            X.normalize().getXCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1 ||
            X.normalize().getYCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
            X.normalize().getYCoord().toBigInteger().compareTo(q.subtract(BigInteger.ONE)) == 1)
        {
            return false;
        }
        // Check X lies on the curve
        // TODO

        // check that hX = infinity
        // TODO if (X.multiply(h).isInfinity())

        // check if V = G*r + X*h
        ECPoint V = G.multiply(zkp.getR()).add(X.multiply(zkp.getH()));
        digest.update(G.getEncoded(true), 0, G.getEncodedLength(true));
        digest.update(V.getEncoded(true), 0, V.getEncodedLength(true));
        digest.update(X.getEncoded(true), 0, X.getEncodedLength(true));
        digest.update(proverIdentity, 0, proverIdentity.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return zkp.getH().equals(new BigInteger(1, output));
    }
    public BigInteger getRandomInCurve()
    {
        return BigIntegers.createRandomInRange(BigInteger.ONE, n.subtract(BigInteger.ONE), random);
    }
    public OwlCredentialHashes getCredentialHashes(byte[] identity, byte[] password)
    {
        digest.update(identity, 0, identity.length);
        digest.update(password, 0, password.length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        BigInteger t = new BigInteger(1, output).mod(n);

        digest.update(output, 0, output.length);
        output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        BigInteger pi = new BigInteger(1, output).mod(n);

        return new OwlCredentialHashes(t, pi);
    }
    public BigInteger generateTranscript(
        ECPoint K,
        byte[] userIdentity,
        ECPoint X1,
        ECPoint X2,
        OwlZKP PI1,
        OwlZKP PI2,
        byte[] serverIdentity,
        ECPoint X3,
        ECPoint X4,
        OwlZKP PI3,
        OwlZKP PI4,
        ECPoint beta,
        OwlZKP PIbeta,
        ECPoint alpha,
        OwlZKP PIalpha
    )
    {
        digest.update(K.getEncoded(true), 0, K.getEncodedLength(true));
        digest.update(userIdentity, 0, userIdentity.length);
        digest.update(X1.getEncoded(true), 0, X1.getEncodedLength(true));
        digest.update(X2.getEncoded(true), 0, X2.getEncodedLength(true));
        digest.update(PI1.getH().toByteArray(), 0, PI1.getH().toByteArray().length);
        digest.update(PI1.getR().toByteArray(), 0, PI1.getR().toByteArray().length);
        digest.update(PI2.getH().toByteArray(), 0, PI2.getH().toByteArray().length);
        digest.update(PI2.getR().toByteArray(), 0, PI2.getR().toByteArray().length);
        digest.update(serverIdentity, 0, serverIdentity.length);
        digest.update(X3.getEncoded(true), 0, X3.getEncodedLength(true));
        digest.update(X4.getEncoded(true), 0, X4.getEncodedLength(true));
        digest.update(PI3.getH().toByteArray(), 0, PI3.getH().toByteArray().length);
        digest.update(PI3.getR().toByteArray(), 0, PI3.getR().toByteArray().length);
        digest.update(PI4.getH().toByteArray(), 0, PI4.getH().toByteArray().length);
        digest.update(PI4.getR().toByteArray(), 0, PI4.getR().toByteArray().length);
        digest.update(beta.getEncoded(true), 0, beta.getEncodedLength(true));
        digest.update(PIbeta.getH().toByteArray(), 0, PIbeta.getH().toByteArray().length);
        digest.update(PIbeta.getR().toByteArray(), 0, PIbeta.getR().toByteArray().length);
        digest.update(alpha.getEncoded(true), 0, alpha.getEncodedLength(true));
        digest.update(PIalpha.getH().toByteArray(), 0, PIalpha.getH().toByteArray().length);
        digest.update(PIalpha.getR().toByteArray(), 0, PIalpha.getR().toByteArray().length);
        byte[] output = new byte[digest.getDigestSize()];
        digest.doFinal(output, 0);
        return new BigInteger(1, output);
    }
}
