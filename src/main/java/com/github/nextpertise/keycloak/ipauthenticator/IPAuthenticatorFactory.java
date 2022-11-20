package com.github.nextpertise.keycloak.ipauthenticator;

import static java.util.Arrays.asList;
import static org.keycloak.authentication.authenticators.browser.ConditionalOtpFormAuthenticator.OTP_CONTROL_USER_ATTRIBUTE;
import static org.keycloak.authentication.authenticators.browser.ConditionalOtpFormAuthenticator.SKIP_OTP_ROLE;
import static org.keycloak.provider.ProviderConfigProperty.*;

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
    static final String TRUST_X_REAL_IP_HEADER = "trust_x_real_ip_header";
    static final String TRUSTED_NETWORKS = "trusted_networks";

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
        return true;
    }

    @Override
    public String getHelpText() {
        return "Limits access to only allowed IP subnets";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        ProviderConfigProperty failOrForceOtp = new ProviderConfigProperty();
        failOrForceOtp.setType(BOOLEAN_TYPE);
        failOrForceOtp.setName(FAIL_OR_FORCE_OTP);
        failOrForceOtp.setLabel("When enabled this module will return a failure " +
                "if remote ip-address does not match.");
        failOrForceOtp.setHelpText(String.format("This module can either fail or force otp. " +
                "OTP is enforced by user attribute: '%s'.", IPAuthenticator.IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE));
        failOrForceOtp.setDefaultValue(true);

        ProviderConfigProperty trustXRealIpHeader = new ProviderConfigProperty();
        trustXRealIpHeader.setType(BOOLEAN_TYPE);
        trustXRealIpHeader.setName(TRUST_X_REAL_IP_HEADER);
        trustXRealIpHeader.setLabel("Respect X-REAL-IP Header");
        trustXRealIpHeader.setHelpText("Respect IP-address as defined X-REAL-IP header, " +
                "if not defined use TCP remote IP.");
        trustXRealIpHeader.setDefaultValue(false);

        ProviderConfigProperty trustedNetworks = new ProviderConfigProperty();
        trustedNetworks.setType(STRING_TYPE);
        trustedNetworks.setName(TRUSTED_NETWORKS);
        trustedNetworks.setLabel("Allow X-REAL-IP only from trusted networks.");
        trustedNetworks.setHelpText("Allow X-REAL-IP only from trusted networks. By default allow all networks.");
        trustedNetworks.setDefaultValue("[{\"subnet\": \"0.0.0.0/0\", \"description\": \"Allow all IPv4 networks\"}]");

        return asList(failOrForceOtp, trustXRealIpHeader, trustedNetworks);
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
