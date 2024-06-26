package org.bouncycastle.crypto.agreement.owl;

import org.bouncycastle.crypto.agreement.owl.messages.InitialLoginResponse;
import org.bouncycastle.crypto.agreement.owl.messages.ServerInitialValues;

public class OwlServerInitialLoginValues {
    private InitialLoginResponse response;
    private ServerInitialValues initialValues;

    public OwlServerInitialLoginValues(InitialLoginResponse response, ServerInitialValues initialValues) {
        this.response = response;
        this.initialValues = initialValues;
    }

    public InitialLoginResponse getResponse() {
        return response;
    }

    public ServerInitialValues getInitialValues() {
        return initialValues;
    }
}
