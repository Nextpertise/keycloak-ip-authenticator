package com.github.nextpertise.keycloak.ipauthenticator;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.*;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

public class IPAuthenticator implements Authenticator {

    private static final Logger logger = Logger.getLogger(IPAuthenticator.class);
    private static final String IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE = "ip_based_otp_conditional";

    public static boolean verify_ip_address(String remote_ip, List<IpItem> IpWhitelist) {
        for (IpItem item : IpWhitelist) {
            IpAddressMatcher matcherObject = new IpAddressMatcher(item.subnet);
            if(matcherObject.matches(remote_ip)) {
                return true;
            }
        }
        return false;
    }

    public Response errorResponse(int status, String error, String errorDescription) {
        OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(error, errorDescription);
        return Response.status(status).entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        logger.infof("Enter IP Authenticater");
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        Map<String, List<String>> UserAttributes = user.getAttributes();
        String remoteIPAddress = context.getConnection().getRemoteAddr(); // TODO: Check if X-REAL-IP header is set when remoteAddr equals to X
        Boolean match = false;

        if(UserAttributes.containsKey("ip_whitelisting")) {
            ObjectMapper objectMapper = new ObjectMapper();
            if (UserAttributes.get("ip_whitelisting").size() > 0) {
                List<IpItem> IpWhitelist = null;
                try {
                    IpWhitelist = objectMapper.readValue(UserAttributes.get("ip_whitelisting")
                            .get(0), new TypeReference<List<IpItem>>() {
                    });
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
                if (this.verify_ip_address(remoteIPAddress, IpWhitelist)) {
                    match = true;
                }
            }
        }

        if (!match) {
            logger.infof("IP Authenticater: IPs do not match. Realm %s expected %s but user %s logged from %s",
                    realm.getName(), "TODO", user.getUsername(), remoteIPAddress);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid IP address");
            if (this.getFailOrForceOtp(context)) {
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
                return;
            }
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
            context.success();
            return;
        }

        logger.infof("IP Authenticater: Pass.");
        if (!this.getFailOrForceOtp(context)) {
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("skip"));
        }
        context.success();
    }

    private Boolean getFailOrForceOtp(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        return Boolean.valueOf(config.get(IPAuthenticatorFactory.FAIL_OR_FORCE_OTP));
    }

    @Override
    public void action(AuthenticationFlowContext context) {
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }

}
