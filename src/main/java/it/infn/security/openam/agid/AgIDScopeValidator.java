package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggrConfigurationFactory;
import it.infn.security.openam.aggregator.AttributeAggregator;
import it.infn.security.openam.aggregator.AuthorityDiscovery;
import it.infn.security.openam.aggregator.AuthorityDiscoveryFactory;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.UserInfoClaims;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.openam.oauth2.IdentityManager;
import org.forgerock.openam.oauth2.OpenAMScopeValidator;
import org.forgerock.openam.scripting.ScriptConstants;
import org.forgerock.openam.scripting.ScriptEvaluator;
import org.forgerock.openam.scripting.service.ScriptingServiceFactory;
import org.forgerock.openam.utils.OpenAMSettings;
import org.forgerock.openidconnect.OpenIDTokenIssuer;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.restlet.Request;
import org.restlet.ext.servlet.ServletUtils;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.shared.debug.Debug;

public class AgIDScopeValidator
    extends OpenAMScopeValidator {

    private static Debug debug = Debug.getInstance("Aggregator");

    public static final String SPID_SCOPE = "spid";

    private final OpenAMSettings openAMSettings;

    private final IdentityManager identityManager;

    @Inject
    public AgIDScopeValidator(IdentityManager identityManager, OpenIDTokenIssuer openIDTokenIssuer,
            OAuth2ProviderSettingsFactory providerSettingsFactory, OpenAMSettings openAMSettings,
            @Named(ScriptConstants.OIDC_CLAIMS_NAME) ScriptEvaluator scriptEvaluator,
            OpenIdConnectClientRegistrationStore clientRegistrationStore,
            ScriptingServiceFactory scriptingServiceFactory) {
        super(identityManager, openIDTokenIssuer, providerSettingsFactory, openAMSettings, scriptEvaluator,
                clientRegistrationStore, scriptingServiceFactory);
        this.openAMSettings = openAMSettings;
        this.identityManager = identityManager;

    }

    @Override
    public UserInfoClaims getUserInfo(AccessToken accessToken, OAuth2Request request)
        throws UnauthorizedClientException, NotFoundException {

        UserInfoClaims userInfo = super.getUserInfo(accessToken, request);

        try {

            Map<String, Object> claimTable = new HashMap<String, Object>();
            Map<String, List<String>> compositeScopes = userInfo.getCompositeScopes();
            List<String> spidAttrList = compositeScopes.containsKey(SPID_SCOPE) ? compositeScopes.get(SPID_SCOPE)
                    : new ArrayList<String>();

            if (accessToken != null) {

                debug.message("Checking the access token");
                String realm = accessToken.getRealm();
                String ownerId = accessToken.getResourceOwnerId();

                AMIdentity amId = identityManager.getResourceOwnerIdentity(ownerId, realm);
                @SuppressWarnings("unchecked")
                Set<String> tmpSet = amId.getAttribute(AgIDAggrConstants.UID_KEY);
                if (tmpSet == null || tmpSet.size() == 0)
                    throw new NotFoundException("No " + AgIDAggrConstants.UID_KEY + " for " + ownerId);
                String spidCode = tmpSet.iterator().next();

                debug.message("Aggregate attributes for " + spidCode);
                AggrConfiguration config = AggrConfigurationFactory.getInstance(realm);
                AuthorityDiscovery disco = AuthorityDiscoveryFactory.getInstance(config);
                AttributeAggregator aggregator = new AttributeAggregator(disco, config);

                Map<String, Set<String>> attributes = aggregator.getAttributes(spidCode);
                for (String attrName : attributes.keySet()) {
                    spidAttrList.add(attrName);
                    String attrValue = concatValues(attributes.get(attrName));
                    claimTable.put(attrName, attrValue);
                    debug.message("Create claim " + attrName + ": " + attrValue);
                }

            } else {

                debug.message("Checking the SSO session");
                SSOToken ssoToken = getUsersSession(request);
                String tmps = ssoToken.getProperty(AgIDAggrConstants.SPID_DICT);
                String[] attrNames = tmps != null ? tmps.split(",") : new String[0];

                for (String attrName : attrNames) {
                    spidAttrList.add(attrName);
                    String attrValue = ssoToken.getProperty(attrName);
                    claimTable.put(attrName, attrValue);
                    debug.message("Create claim " + attrName + ": " + attrValue);
                }

            }

            userInfo.getValues().putAll(claimTable);
            compositeScopes.put(SPID_SCOPE, spidAttrList);
            userInfo.getCompositeScopes().putAll(compositeScopes);

        } catch (Throwable th) {
            debug.error(th.getMessage(), th);
        }

        return userInfo;
    }

    /*
     * Imported from org.forgerock.openam.oauth2.OpenAMScopeValidator
     */
    private SSOToken getUsersSession(OAuth2Request request) {
        String sessionId = request.getSession();
        if (sessionId == null) {
            final HttpServletRequest req = ServletUtils.getRequest(request.<Request> getRequest());
            if (req.getCookies() != null) {
                final String cookieName = openAMSettings.getSSOCookieName();
                for (final Cookie cookie : req.getCookies()) {
                    if (cookie.getName().equals(cookieName)) {
                        sessionId = cookie.getValue();
                    }
                }
            }
        }
        SSOToken ssoToken = null;
        if (sessionId != null) {
            try {
                ssoToken = SSOTokenManager.getInstance().createSSOToken(sessionId);
            } catch (SSOException e) {
                debug.message("Session Id is not valid");
            }
        }
        return ssoToken;
    }

    private String concatValues(Collection<String> vItems) {
        /*
         * TODO check length and throw exception
         */
        StringBuffer buff = new StringBuffer();
        for (String value : vItems) {
            if (buff.length() > 0)
                buff.append(",");
            buff.append(value.trim());
        }
        return buff.toString();
    }

}