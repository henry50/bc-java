package org.bouncycastle.crypto.agreement.owl;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.owl.messages.FinalizeLoginRequest;
import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginRequest;
import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginResponse;
import org.bouncycastle.crypto.agreement.owl.messages.RegisterRequest;
import org.bouncycastle.crypto.agreement.owl.messages.ServerInitialValues;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

public class OwlServer {
    private byte[] serverIdentity;
    private BigInteger n;
    private ECPoint G;
    private OwlUtil util;

    /**
     * Initialises the server using n and G curve parameters
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
     * Initialises the server using an elliptic curve parameter spec
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
     * Generate user credentials from client register message
     * 
     * @param request Client register request message
     * @return User credentials object
     */
    public OwlUserCredentials register(RegisterRequest request) {
        BigInteger x3 = util.getRandomInCurve();
        ECPoint X3 = G.multiply(x3);
        OwlZKP PI3 = util.createZKP(x3, X3, G, serverIdentity);

        return new OwlUserCredentials(X3, PI3, request.getPi(), request.getT());
    }

    /**
     * Generate initial login response and temporary initial values object from
     * client identity, request and credentials
     * 
     * @param identity    The user's identity
     * @param request     Client's initial login request
     * @param credentials The user's credentials
     * @return Initial login values object
     */
    public OwlServerInitialLoginValues initialLogin(byte[] identity, InitialLoginRequest request,
            OwlUserCredentials credentials) throws CryptoException {
        // Verify ZKPs for x1 and x2
        if (!(util.verifyZKP(request.getPI1(), request.getX1(), G, identity) &&
                util.verifyZKP(request.getPI2(), request.getX2(), G, identity))) {
            throw new CryptoException("Failed to verify ZKPs");
        }

        BigInteger x4 = util.getRandomInCurve();
        ECPoint X4 = G.multiply(x4);
        OwlZKP PI4 = util.createZKP(x4, X4, G, serverIdentity);

        BigInteger secret = x4.multiply(credentials.getPi());
        ECPoint betaGenerator = request.getX1().add(request.getX2()).add(credentials.getX3());
        ECPoint beta = betaGenerator.multiply(secret);
        OwlZKP PIbeta = util.createZKP(secret, beta, betaGenerator, serverIdentity);

        InitialLoginResponse response = new InitialLoginResponse(credentials.getX3(), X4, credentials.getPI3(), PI4,
                beta, PIbeta);
        ServerInitialValues initialValues = new ServerInitialValues(credentials.getT(), credentials.getPi(), x4,
                request.getX1(), request.getX2(), credentials.getX3(), X4, beta, request.getPI1(), request.getPI2(),
                credentials.getPI3(), PI4, PIbeta);
        return new OwlServerInitialLoginValues(response, initialValues);
    }

    /**
     * Derive the shared key given the user's identity, request and the server
     * initial values
     * 
     * @param identity      The user's identity
     * @param request       The client finalize login request
     * @param initialValues The initial values from OwlServer.initialLogin
     * @return The mutually derived key
     * @throws CryptoException If ZKP verification or authentication fail
     */
    public byte[] finalizeLogin(byte[] identity, FinalizeLoginRequest request, ServerInitialValues initialValues)
            throws CryptoException {

        ECPoint alphaGenerator = initialValues.getX1().add(initialValues.getX3()).add(initialValues.getX4());

        // verify ZKP for alpha
        if (!util.verifyZKP(request.getPIalpha(), request.getAlpha(), alphaGenerator, identity)) {
            throw new CryptoException("Failed to verify ZKPs");
        }
        // K = (alpha - (X2 * ((x4 * pi) mod n))) * x4
        ECPoint K = request.getAlpha().subtract(
                initialValues.getX2().multiply(
                        initialValues.getx4().multiply(initialValues.getPi()).mod(n)))
                .multiply(initialValues.getx4());

        BigInteger h = util.generateTranscript(K, identity, initialValues.getX1(), initialValues.getX2(),
                initialValues.getPI1(), initialValues.getPI2(), serverIdentity, initialValues.getX3(),
                initialValues.getX4(), initialValues.getPI3(), initialValues.getPI4(), initialValues.getBeta(),
                initialValues.getPIbeta(), request.getAlpha(), request.getPIalpha());

        // Check G * r + T * h == X1
        ECPoint part1 = G.multiply(request.getR()); // G * r
        ECPoint part2 = initialValues.getT().multiply(h.mod(n)); // T * (h mod n)
        ECPoint part3 = part1.add(part2); // G * r + T * h
        boolean part4 = part3.equals(initialValues.getX1()); // G * r + T * h ?= X1
        if (!part4) {
            throw new CryptoException("Authentication failed");
        }

        return util.getFinalKey(K);
    }
}
