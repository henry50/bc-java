package org.bouncycastle.crypto.agreement.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.math.ec.ECPoint;

import static org.junit.Assert.assertArrayEquals;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.agreement.owl.OwlClient;
import org.bouncycastle.crypto.agreement.owl.OwlClientFinalValues;
import org.bouncycastle.crypto.agreement.owl.OwlServer;
import org.bouncycastle.crypto.agreement.owl.OwlServerInitialLoginValues;
import org.bouncycastle.crypto.agreement.owl.OwlUserCredentials;
import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginRequest;
import org.bouncycastle.crypto.agreement.owl.messages.RegisterRequest;

public class OwlTest extends TestCase {
    private X9ECParameters spec = ECNamedCurveTable.getByName("prime256v1");
    private BigInteger n = spec.getN();
    private ECPoint G = spec.getG();
    private SecureRandom random = new SecureRandom();
    private Digest digest = SHA256Digest.newInstance();
    private byte[] clientIdentity = "username".getBytes();
    private byte[] password = "password".getBytes();
    private byte[] serverIdentity = "localhost".getBytes();

    public void testConstruction() {
        OwlClient client = new OwlClient();
        client.init(serverIdentity, n, G, digest, random);

        OwlServer server = new OwlServer();
        server.init(serverIdentity, n, G, digest, random);
    }

    public void testFullProtocol() throws CryptoException {
        OwlClient client = new OwlClient();
        client.init(serverIdentity, n, G, digest, random);
        OwlServer server = new OwlServer();
        server.init(serverIdentity, n, G, digest, random);

        // registration
        RegisterRequest regRequest = client.register(clientIdentity, password);
        // send regRequest -> server
        OwlUserCredentials credentials = server.register(regRequest);
        // the server stores credentials alongside the client identity

        // login
        InitialLoginRequest initRequest = client.initialLogin(clientIdentity, password);
        // send initRequest -> server
        OwlServerInitialLoginValues initResponseValues = server.initialLogin(clientIdentity, initRequest, credentials);
        // store initResponseValues.getInitialValues() alongside client identity
        // send initResponseValues.getResponse() -> client
        OwlClientFinalValues finalRequest = client.finalizeLogin(initResponseValues.getResponse());
        // send finalRequest.getFinalizeLoginRequest() -> server
        // if finalizeLogin succeeds then authentication is successful
        byte[] serverKey = server.finalizeLogin(clientIdentity, finalRequest.getFinalizeLoginRequest(),
                initResponseValues.getInitialValues());
        // assert the derived keys are equal
        assertArrayEquals(finalRequest.getKey(), serverKey);
    }
}
