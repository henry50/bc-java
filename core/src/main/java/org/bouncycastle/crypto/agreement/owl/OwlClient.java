package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.owl.messages.FinalizeLoginRequest;
import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginRequest;
import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginResponse;
import org.bouncycastle.crypto.agreement.owl.messages.RegisterRequest;
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
    private boolean clientInitialized = false;
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
     * Generate client registration values to send to the server
     * 
     * @param identity The user's identity
     * @param password The user's password
     * @return Client register message
     */
    public RegisterRequest register(byte[] identity, byte[] password) {
        // t = H(U || w) mod n
        // pi = H(t) mod n
        OwlCredentialHashes hashes = util.getCredentialHashes(identity, password);

        // T = G * t
        ECPoint T = G.multiply(hashes.gett());

        return new RegisterRequest(hashes.gett(), hashes.getPi(), T);
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
        // t = H(U || w) mod n
        // pi = H(t) mod n
        OwlCredentialHashes hashes = util.getCredentialHashes(identity, password);
        this.t = hashes.gett();
        this.pi = hashes.getPi();

        // x1 = [1, n-1]
        this.x1 = util.getRandomInCurve();
        // X1 = G * x1
        this.X1 = G.multiply(x1);

        // x2 = [1, n-1]
        this.x2 = util.getRandomInCurve();
        // X2 = G * x2
        this.X2 = G.multiply(x2);

        // PI1 = ZKP{x1}
        this.PI1 = util.createZKP(x1, X1, G, identity);
        // PI2 = ZKP{x2}
        this.PI2 = util.createZKP(x2, X2, G, identity);

        clientInitialized = true;

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
        // Check the initialLogin has been called before continuing
        if (!clientInitialized) {
            throw new CryptoException("Cannot finalize login before initial login");
        }
        // betaG = X1 + X2 + X3
        ECPoint betaGenerator = X1.add(X2).add(response.getX3());
        // verify ZKPs for X3, X4 and beta
        if (!(util.verifyZKP(response.getPI3(), response.getX3(), G, serverIdentity) &&
                util.verifyZKP(response.getPI4(), response.getX4(), G, serverIdentity) &&
                util.verifyZKP(response.getPIbeta(), response.getBeta(), betaGenerator, serverIdentity))) {
            throw new CryptoException("Failed to verify ZKPs");
        }
        // secret = (x2 * pi) mod n
        BigInteger secret = x2.multiply(pi).mod(n);
        // alphaG = X1 + X3 + X4
        ECPoint alphaGenerator = X1.add(response.getX3()).add(response.getX4());
        // alpha = alphaG * secret
        ECPoint alpha = alphaGenerator.multiply(secret);
        // PIalpha = ZKP{secret}
        OwlZKP PIalpha = util.createZKP(secret, alpha, alphaGenerator, identity);

        // K = (beta - (X4 * secret)) * x2
        ECPoint K = response.getBeta().subtract(response.getX4().multiply(secret)).multiply(x2);

        // h = H(K || Transcript)
        BigInteger h = util.generateTranscript(K, identity, X1, X2, PI1, PI2, serverIdentity, response.getX3(),
                response.getX4(), response.getPI3(), response.getPI4(), response.getBeta(),
                response.getPIbeta(), alpha, PIalpha);

        // r = x1 - (t * h) mod n
        BigInteger r = x1.subtract(t.multiply(h)).mod(n);
        // k = H(K)
        byte[] k = util.getFinalKey(K);

        FinalizeLoginRequest finalizeLoginRequest = new FinalizeLoginRequest(alpha, PIalpha, r);
        return new OwlClientFinalValues(k, finalizeLoginRequest);
    }
}
