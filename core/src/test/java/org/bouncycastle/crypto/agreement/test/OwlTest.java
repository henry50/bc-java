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
import org.bouncycastle.crypto.agreement.owl.OwlAuthenticationFailure;
import org.bouncycastle.crypto.agreement.owl.OwlClient;
import org.bouncycastle.crypto.agreement.owl.OwlClientFinalValues;
import org.bouncycastle.crypto.agreement.owl.OwlServer;
import org.bouncycastle.crypto.agreement.owl.OwlServerInitialLoginValues;
import org.bouncycastle.crypto.agreement.owl.OwlUninitializedClientException;
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
        new OwlClient(serverIdentity, n, G, digest, random);

        new OwlServer(serverIdentity, n, G, digest, random);
    }

    public void testFullProtocol() throws CryptoException {
        OwlClient client = new OwlClient(serverIdentity, n, G, digest, random);
        OwlServer server = new OwlServer(serverIdentity, n, G, digest, random);

        // registration
        RegisterRequest regRequest = client.register(clientIdentity, password);
        // send regRequest -> server
        OwlUserCredentials credentials = server.register(regRequest);
        // the server stores credentials alongside the client identity

        // login
        InitialLoginRequest initRequest = client.initialLogin(clientIdentity, password);
        // send initRequest -> server
        // the server would have to retrieve the credentials from a database using the
        // client identity
        OwlServerInitialLoginValues initResponseValues = server.initialLogin(clientIdentity, initRequest, credentials);
        // store initResponseValues.getInitialValues() alongside client identity
        // send initResponseValues.getResponse() -> client
        OwlClientFinalValues finalRequest = client.finalizeLogin(initResponseValues.getResponse());
        // send finalRequest.getFinalizeLoginRequest() -> server
        // the ServerInitialValues would have to be retrieved from a database and can be
        // deleted after this method completes
        // if finalizeLogin succeeds then authentication is successful
        byte[] serverKey = server.finalizeLogin(clientIdentity, finalRequest.getFinalizeLoginRequest(),
                initResponseValues.getInitialValues());
        // assert the derived keys are equal
        assertArrayEquals(finalRequest.getKey(), serverKey);
    }

    public void testIncorrectPassword() throws CryptoException {
        byte[] incorrectPassword = "incorrect".getBytes();
        OwlClient client = new OwlClient(serverIdentity, n, G, digest, random);
        OwlServer server = new OwlServer(serverIdentity, n, G, digest, random);
        // register with correct password
        RegisterRequest regRequest = client.register(clientIdentity, password);
        OwlUserCredentials credentials = server.register(regRequest);

        // login with incorrect password
        InitialLoginRequest initRequest = client.initialLogin(clientIdentity, incorrectPassword);
        OwlServerInitialLoginValues initResponseValues = server.initialLogin(clientIdentity, initRequest, credentials);
        OwlClientFinalValues finalRequest = client.finalizeLogin(initResponseValues.getResponse());
        try {
            server.finalizeLogin(clientIdentity, finalRequest.getFinalizeLoginRequest(),
                    initResponseValues.getInitialValues());
        } catch (OwlAuthenticationFailure e) {
            // test successful
            return;
        }
        fail("Incorrect password did not cause authentication failure");
    }

    public void testUninitializedClient() throws CryptoException {
        OwlClient client = new OwlClient(serverIdentity, n, G, digest, random);
        OwlServer server = new OwlServer(serverIdentity, n, G, digest, random);
        RegisterRequest regRequest = client.register(clientIdentity, password);
        OwlUserCredentials credentials = server.register(regRequest);
        InitialLoginRequest initRequest = client.initialLogin(clientIdentity, password);
        OwlServerInitialLoginValues initResponseValues = server.initialLogin(clientIdentity, initRequest, credentials);

        // initialise new client
        client = new OwlClient(serverIdentity, n, G, digest, random);
        try {
            client.finalizeLogin(initResponseValues.getResponse());
        } catch (OwlUninitializedClientException e) {
            // test successful
            return;
        }
        fail("Uninitialized client did not cause error");
    }
}
