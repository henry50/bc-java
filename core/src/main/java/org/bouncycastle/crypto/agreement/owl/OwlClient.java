package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implements the client side Owl protocol.
 */
public class OwlClient
{
    protected BigInteger n;
    protected ECPoint G;
    protected OwlUtil util;

    // Values created during initial login and used in finalize login
    protected byte[] identity;
    protected BigInteger t;
    protected BigInteger pi;
    protected BigInteger x1;
    protected BigInteger x2;
    protected ECPoint X1;
    protected ECPoint X2;
    protected OwlZKP PI1;
    protected OwlZKP PI2;
    
    protected Digest digest;
    protected SecureRandom random;

    /**
     * Initialises the client using n and G curve parameters
     * @param n Order of the curve
     * @param G Curve generator point
     * @param digest Digest algorithm
     * @param random Secure random number generator
     */
    public void init(BigInteger n, ECPoint G, Digest digest, SecureRandom random)
    {
        this.n = n;
        this.G = G;
        this.digest = digest;
        this.random = random;
        this.util = new OwlUtil(n, digest, random);
    }

    /**
     * Initialises the client using an elliptic curve parameter spec
     * @param spec Elliptic curve specification 
     * @param digest Digest algorithm
     * @param random Secure random number generator
     */
    public void init(ECParameterSpec spec, Digest digest, SecureRandom random)
    {
        init(spec.getN(), spec.getG(), digest, random);
    }

    /**
     * Generate client registration values to send to the server
     * @param identity The user's identity
     * @param password The user's password
     * @return Client register message
     */
    public OwlClientRegisterMessage register(byte[] identity, byte[] password)
    {
        OwlCredentialHashes hashes = util.getCredentialHashes(identity, password);

        ECPoint T = G.multiply(hashes.getPi());

        return new OwlClientRegisterMessage(hashes.getT(), hashes.getPi(), T);
    }

    /**
     * Generate client initial login values to send to the server
     * @param identity The user's identity
     * @param password The user's password
     * @return Client initial login message
     */
    public OwlClientInitialLoginMessage initialLogin(byte[] identity, byte[] password)
    {
        this.identity = identity;
        OwlCredentialHashes hashes = util.getCredentialHashes(identity, password);
        this.t = hashes.getT();
        this.pi = hashes.getPi();

        this.x1 = util.getRandomInCurve();
        this.X1 = G.multiply(x1);

        this.x2 = util.getRandomInCurve();
        this.X2 = G.multiply(x2);

        this.PI1 = util.createZKP(x1, X1, G, identity);
        this.PI2 = util.createZKP(x2, X2, G, identity);

        return new OwlClientInitialLoginMessage(X1, X2, PI1, PI2);
    }

    /**
     * Generate client finalize login message to send to the server
     * @param initialResponse Initial response message from server
     * @return Object containing derived key and final login message
     * @throws CryptoException If ZKP verification fails
     */
    public OwlClientFinalValues finalizeLogin(ECPoint X3, ECPoint X4, OwlZKP PI3, OwlZKP PI4, ECPoint beta, OwlZKP PIbeta) throws CryptoException
    {
        // TODO make this the actual identity
        byte[] serverIdentity = {0};
        // TODO change ONE to curve q
        // verify ZKPs for X3, X4 and beta
        if(util.verifyZKP(PI3, G, X3, BigInteger.ONE, serverIdentity) &&
           util.verifyZKP(PI4, G, X4, BigInteger.ONE, serverIdentity) &&
           util.verifyZKP(PIbeta, G, beta, BigInteger.ONE, serverIdentity)
        ){
            throw new CryptoException("Failed to verify ZKPs");
        }
        ECPoint alpha = X1.add(X3).add(X4).multiply(x2.multiply(pi));
        OwlZKP PIalpha = util.createZKP(x2.multiply(pi), alpha, X1.add(X3).add(X4), serverIdentity);
        ECPoint K = beta.subtract(X4.multiply(x2.multiply(pi))).multiply(x2);
        
        BigInteger h = util.generateTranscript(K, identity, X1, X2, PI1, PI2, serverIdentity, X3, X4, PI3, PI4, beta, PIbeta, alpha, PIalpha);
        BigInteger r = x1.subtract(t.multiply(h)).mod(n);
        digest.update(K.getEncoded(true), 0, K.getEncodedLength(true));
        byte[] k = new byte[digest.getDigestSize()];
        digest.doFinal(k, 0);
        
        OwlClientFinalizeLoginMessage finalizeLoginMessage = new OwlClientFinalizeLoginMessage(alpha, PIalpha, r);
        return new OwlClientFinalValues(k, finalizeLoginMessage);
    }
}
