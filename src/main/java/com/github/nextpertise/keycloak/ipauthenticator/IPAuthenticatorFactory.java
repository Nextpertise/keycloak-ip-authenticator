package com.github.nextpertise.keycloak.ipauthenticator;

import static org.keycloak.provider.ProviderConfigProperty.BOOLEAN_TYPE;
import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class IPAuthenticatorFactory implements AuthenticatorFactory {

    public static final String ID = "ipauthenticator";

    private static final Authenticator AUTHENTICATOR_INSTANCE = new IPAuthenticator();
    static final String FAIL_OR_FORCE_OTP = "fail_or_force_otp";

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return AUTHENTICATOR_INSTANCE;
    }

    @Override
    public String getDisplayType() {
        return "IP Authenticator";
    }

    @Override
    public boolean isConfigurable() { return true; }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return new AuthenticationExecutionModel.Requirement[] { AuthenticationExecutionModel.Requirement.REQUIRED,
                AuthenticationExecutionModel.Requirement.ALTERNATIVE, AuthenticationExecutionModel.Requirement.DISABLED
        };
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Limits access to only allowed IP subnets";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty name = new ProviderConfigProperty();

        name.setType(BOOLEAN_TYPE);
        name.setName(FAIL_OR_FORCE_OTP);
        name.setLabel("When enabled this module will return a failure if remote ip-address does not match.");
        name.setHelpText("This module can either fail or force otp. OTP is enforced by user attribute: 'ip_based_otp_conditional'."); // TODO: 'ip_based_otp_conditional' can be loaded from var.

        return Collections.singletonList(name);
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public void init(Config.Scope scope) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }
}
