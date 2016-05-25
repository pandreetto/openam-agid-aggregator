package it.infn.security.openam.utils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.forgerock.oauth2.core.UserInfoClaims;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.shared.debug.Debug;

public class OAuth2ClaimsBuilder {

    public static final String SPID_SCOPE = "spid";

    /**
     * This method returns a the SPID attributes, or claims, contained in the session token. All the claims are mapped
     * into the "spid" scope.
     * 
     * @param token
     *            The user's session object, if present the request contains the session cookie, may be null
     * @param scopes
     *            The requested scopes, never null
     * @param requestedClaims
     *            If not empty the request contains a claims parameter and server has enabled
     *            claims_parameter_supported, map of requested claims to possible values, otherwise empty, requested
     *            claims with no requested values will have a key but no value in the map. A key with a single value in
     *            its Set indicates this is the only value that should be returned. Never null
     * @param logger
     *            The "OAuth2Provider" debug logger instance, never null
     * @return A Map of SPID claims to be added to the id_token claims
     */
    public static UserInfoClaims getUserInfoClaims(SSOToken token, Collection<String> scopes,
            Map<String, Set<String>> requestedClaims, Debug logger) {

        Map<String, Object> claimTable = new HashMap<String, Object>();
        Map<String, List<String>> compositeScopes = new HashMap<String, List<String>>();

        if (token == null) {
            logger.error("Session not available");
            return new UserInfoClaims(claimTable, compositeScopes);
        }

        if (scopes.size() > 0 && !scopes.contains(SPID_SCOPE)) {
            logger.message("Missing scope " + SPID_SCOPE + " but go on anyway");
            // return new UserInfoClaims(claimTable, compositeScopes);
        }

        try {

            String tmps = token.getProperty("spid_dict");
            String[] attrNames = tmps != null ? tmps.split(",") : new String[0];

            List<String> spidAttrList = new ArrayList<String>();
            for (String attrName : attrNames) {
                spidAttrList.add(attrName);
                claimTable.put(attrName, token.getProperty(attrName));
                logger.message("Create claim " + attrName + ": " + token.getProperty(attrName));
            }

            /*
             * TODO claims for SPID attributes from IdP
             */

            compositeScopes.put(SPID_SCOPE, spidAttrList);

        } catch (SSOException ssoEx) {
            logger.error(ssoEx.getMessage(), ssoEx);
        }

        return new UserInfoClaims(claimTable, compositeScopes);

    }
}
