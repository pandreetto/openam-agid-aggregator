
import it.infn.security.openam.utils.OAuth2ClaimsBuilder
import org.forgerock.oauth2.core.UserInfoClaims

/*
* Defined variables:
* logger - always presents, the "OAuth2Provider" debug logger instance
* claims - always present, default server provided claims
* session - present if the request contains the session cookie, the user's session object
* identity - always present, the identity of the resource owner
* scopes - always present, the requested scopes
* requestedClaims - Map<String, Set<String>>
*                  always present, not empty if the request contains a claims parameter and server has enabled
*                  claims_parameter_supported, map of requested claims to possible values, otherwise empty,
*                  requested claims with no requested values will have a key but no value in the map. A key with
*                  a single value in its Set indicates this is the only value that should be returned.
* Required to return a Map of claims to be added to the id_token claims
*
* Expected return value structure:
* UserInfoClaims {
*    Map<String, Object> values; // The values of the claims for the user information
*    Map<String, List<String>> compositeScopes; // Mapping of scope name to a list of claim names.
* }
*/

try {

    return OAuth2ClaimsBuilder.getUserInfoClaims(session, scopes, requestedClaims, logger)

} catch (Throwable th) {
    if (logger.warningEnabled()) {
        logger.warning("Cannot build claims", th)
    }
}

return new UserInfoClaims(new HashMap<String, Object>(), new HashMap<String, List<String>>())

