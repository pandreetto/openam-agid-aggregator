package it.infn.security.openam.utils;

import it.infn.security.openam.agid.AgIDAggrConstants;

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

    public static final String[] SPID_IDP_ATTRS = { "spidCode", "name", "familyName", "placeOfBirth", "countyOfBirth",
            "dateOfBirth", "gender", "companyName", "registeredOffice", "fiscalNumber", "ivaCode", "idCard",
            "mobilePhone", "email", "address", "expirationDate", "digitalAddress" };

    /**
     * This method fills in the user claim object with all the SPID attributes contained in the session token. All the
     * claims are mapped into the "spid" scope.
     * 
     * @param userInfoClaims
     *            The user claim object to be filled in with the SPID attributes
     * @param token
     *            The user's session object, if present the request contains the session cookie, may be null
     * @param scopes
     *            The requested scopes, never null
     * @param requestedClaims
     *            If not empty the request contains a claims parameter and server has enabled
     *            claims_parameter_supported, map of requested claims to possible values, otherwise empty, requested
     *            claims with no requested values will have a key but no value in the map. A key with a single value in
     *            its Set indicates this is the only value that should be returned. Never null
     * @param defaultClaims
     *            The default server provided claims, never null
     * @param logger
     *            The "OAuth2Provider" debug logger instance, never null
     */
    public static void fillinSPIDClaims(UserInfoClaims userInfoClaims, SSOToken token, Collection<String> scopes,
            Map<String, Set<String>> requestedClaims, Map<String, Set<String>> defaultClaims, Debug logger) {

        if (userInfoClaims == null)
            return;

        if (token == null) {
            logger.error("Session not available");
            return;
        }

        if (scopes.size() > 0 && !scopes.contains(AgIDAggrConstants.SPID_SCOPE)) {
            logger.message("SPID scope is not required");
            return;
        }

        try {

            Map<String, Object> claimTable = new HashMap<String, Object>();
            Map<String, List<String>> compositeScopes = new HashMap<String, List<String>>();

            String tmps = token.getProperty(AgIDAggrConstants.SPID_DICT);
            String[] attrNames = tmps != null ? tmps.split(",") : new String[0];

            List<String> spidAttrList = new ArrayList<String>();
            for (String attrName : attrNames) {
                spidAttrList.add(attrName);
                claimTable.put(attrName, token.getProperty(attrName));
                logger.message("Create claim " + attrName + ": " + token.getProperty(attrName));
            }

            for (String attrName : SPID_IDP_ATTRS) {
                String tmpa = token.getProperty(attrName);
                if (tmpa != null) {
                    spidAttrList.add(attrName);
                    claimTable.put(attrName, tmpa);
                    logger.message("Create claim " + attrName + ": " + tmpa);
                }
            }

            compositeScopes.put(AgIDAggrConstants.SPID_SCOPE, spidAttrList);

            userInfoClaims.getValues().putAll(claimTable);
            userInfoClaims.getCompositeScopes().putAll(compositeScopes);

        } catch (SSOException ssoEx) {
            logger.error(ssoEx.getMessage(), ssoEx);
        }

    }
}
