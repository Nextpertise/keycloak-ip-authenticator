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
    public static final String IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE = "ip_based_otp_conditional";

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
        logger.infof("IP Authenticator - Enter");
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();
        String remoteIPAddress = context.getConnection().getRemoteAddr();
        String realIPAddress = remoteIPAddress;
        List<IpItem> IpWhitelist = null;

        logger.infof("IP Authenticator - TCP Remote IP address: %s", remoteIPAddress);
        if (getTrustXRealIpHeader(context)) {
            logger.infof("IP Authenticator - Do check X-REAL-IP");
            if (this.verify_ip_address(realIPAddress, getTrustedNetworks(context))) {
                logger.infof("IP Authenticator - TCP Remote IP address " +
                        "from an authenticated network for X-REAL-IP header.");
                if (context.getHttpRequest().getHttpHeaders().getRequestHeader("X-REAL-IP").size() > 0) {
                    realIPAddress = context.getHttpRequest().getHttpHeaders().getRequestHeader("X-REAL-IP").get(0);
                    logger.infof("IP Authenticator - X-REAL-IP address: %s", realIPAddress);
                }
            }
        }

        Boolean match = false;
        IpWhitelist = getUserIpWhitelisting(user);
        if (this.verify_ip_address(realIPAddress, IpWhitelist)) {
            match = true;
        }

        if (!match) {
            logger.infof("IP Authenticator - IPs do not match. " +
                            "Realm %s expected whitelisted IP but user %s logged from %s",
                    realm.getName(), user.getUsername(), realIPAddress);
            Response challengeResponse = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(),
                    "invalid_grant", "Invalid IP address");
            if (this.getFailOrForceOtp(context)) {
                context.failure(AuthenticationFlowError.INVALID_USER, challengeResponse);
                return;
            }
            user.setAttribute(IP_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
            context.success();
            return;
        }

        logger.infof("IP Authenticator - Pass.");
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

    private Boolean getTrustXRealIpHeader(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        return Boolean.valueOf(config.get(IPAuthenticatorFactory.TRUST_X_REAL_IP_HEADER));
    }

    private List getTrustedNetworks(AuthenticationFlowContext context) {
        AuthenticatorConfigModel configModel = context.getAuthenticatorConfig();
        Map<String, String> config = configModel.getConfig();
        ObjectMapper objectMapper = new ObjectMapper();

        List<IpItem> XRealIpTrustedNetworks;
        try {
            XRealIpTrustedNetworks = objectMapper.readValue(config.get(IPAuthenticatorFactory.TRUSTED_NETWORKS)
                    , new TypeReference<List<IpItem>>() {
            });
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

        return XRealIpTrustedNetworks;
    }

    private List getUserIpWhitelisting(UserModel user) {
        Map<String, List<String>> UserAttributes = user.getAttributes();
        List<IpItem> IpWhitelist = Collections.<IpItem>emptyList();
        if(UserAttributes.containsKey("ip_whitelist")) {
            ObjectMapper objectMapper = new ObjectMapper();
            if (UserAttributes.get("ip_whitelist").size() > 0) {
                try {
                    IpWhitelist = objectMapper.readValue(UserAttributes.get("ip_whitelist")
                            .get(0), new TypeReference<List<IpItem>>() {
                    });
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }
        }
        return IpWhitelist;
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
