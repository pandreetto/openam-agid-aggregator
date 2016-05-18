package it.infn.security.openam.utils;

import java.util.ArrayList;
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

    public static UserInfoClaims getUserInfoClaims(SSOToken token, List<String> scopes,
            Map<String, Set<String>> requestedClaims, Debug logger)
        throws SSOException {

        if (token == null)
            throw new SSOException("Session not available");

        Map<String, Object> claimTable = new HashMap<String, Object>();
        Map<String, List<String>> compositeScopes = new HashMap<String, List<String>>();

        if (!scopes.contains(SPID_SCOPE)) {
            return new UserInfoClaims(claimTable, compositeScopes);
        }

        String tmps = token.getProperty("spid_dict");
        String[] attrNames = tmps != null ? tmps.split(",") : new String[0];

        List<String> spidAttrList = new ArrayList<String>();
        for (String attrName : attrNames) {
            spidAttrList.add(attrName);
            claimTable.put(attrName, token.getProperty(attrName));
        }

        /*
         * TODO claims for SPID attributes from IdP
         */

        compositeScopes.put(SPID_SCOPE, spidAttrList);

        return new UserInfoClaims(claimTable, compositeScopes);

    }

}
