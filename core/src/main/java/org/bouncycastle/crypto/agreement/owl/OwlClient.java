package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.owl.messages.FinalizeLoginRequest;
import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginRequest;
import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginResponse;
import org.bouncycastle.crypto.agreement.owl.messages.RegisterRequest;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * Implements the client side Owl protocol.
 */
public class OwlClient {
    private byte[] serverIdentity;
    private BigInteger n;
    private ECPoint G;
    private OwlUtil util;

    // Values created during initial login and used in finalize login
    private byte[] identity;
    private BigInteger t;
    private BigInteger pi;
    private BigInteger x1;
    private BigInteger x2;
    private ECPoint X1;
    private ECPoint X2;
    private OwlZKP PI1;
    private OwlZKP PI2;

    /**
     * Initialises the client using n and G curve parameters
     * 
     * @param serverIdentity The server's identity
     * @param n              Order of the curve
     * @param G              Curve generator point
     * @param digest         Digest algorithm
     * @param random         Secure random number generator
     */
    public void init(byte[] serverIdentity, BigInteger n, ECPoint G, Digest digest, SecureRandom random) {
        this.serverIdentity = serverIdentity;
        this.n = n;
        this.G = G;
        this.util = new OwlUtil(n, digest, random);
    }

    /**
     * Initialises the client using an elliptic curve parameter spec
     * 
     * @param serverIdentity The server's identity
     * @param spec           Elliptic curve specification
     * @param digest         Digest algorithm
     * @param random         Secure random number generator
     */
    public void init(byte[] serverIdentity, ECParameterSpec spec, Digest digest, SecureRandom random) {
        init(serverIdentity, spec.getN(), spec.getG(), digest, random);
    }

    /**
     * Generate client registration values to send to the server
     * 
     * @param identity The user's identity
     * @param password The user's password
     * @return Client register message
     */
    public RegisterRequest register(byte[] identity, byte[] password) {
        OwlCredentialHashes hashes = util.getCredentialHashes(identity, password);

        ECPoint T = G.multiply(hashes.getPi());

        return new RegisterRequest(hashes.getT(), hashes.getPi(), T);
    }

    /**
     * Generate client initial login values to send to the server
     * 
     * @param identity The user's identity
     * @param password The user's password
     * @return Client initial login request
     */
    public InitialLoginRequest initialLogin(byte[] identity, byte[] password) {
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

        return new InitialLoginRequest(X1, X2, PI1, PI2);
    }

    /**
     * Generate client finalize login message to send to the server
     * 
     * @param response Initial response message from server
     * @return Object containing derived key and final login message
     * @throws CryptoException If ZKP verification fails
     */
    public OwlClientFinalValues finalizeLogin(InitialLoginResponse response) throws CryptoException {
        ECPoint betaGenerator = X1.add(X2).add(response.getX3());
        // verify ZKPs for X3, X4 and beta
        if (!(util.verifyZKP(response.getPI3(), response.getX3(), G, serverIdentity) &&
                util.verifyZKP(response.getPI4(), response.getX4(), G, serverIdentity) &&
                util.verifyZKP(response.getPIbeta(), response.getBeta(), betaGenerator, serverIdentity))) {
            throw new CryptoException("Failed to verify ZKPs");
        }
        ECPoint alphaGenerator = X1.add(response.getX3()).add(response.getX4());
        ECPoint alpha = alphaGenerator.multiply(x2.multiply(pi));
        OwlZKP PIalpha = util.createZKP(x2.multiply(pi), alpha, alphaGenerator, identity);

        ECPoint K = response.getBeta().subtract(response.getX4().multiply(x2.multiply(pi))).multiply(x2);

        BigInteger h = util.generateTranscript(K, identity, X1, X2, PI1, PI2, serverIdentity, response.getX3(),
                response.getX4(), response.getPI3(), response.getPI4(), response.getBeta(),
                response.getPIbeta(), alpha, PIalpha);
        
        BigInteger r = x1.subtract(t.multiply(h)).mod(n);
        byte[] k = util.getFinalKey(K);

        FinalizeLoginRequest finalizeLoginRequest = new FinalizeLoginRequest(alpha, PIalpha, r);
        return new OwlClientFinalValues(k, finalizeLoginRequest);
    }
}
