package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggrConfigurationFactory;
import it.infn.security.openam.aggregator.AggregatorException;
import it.infn.security.openam.aggregator.AttributeAggregator;
import it.infn.security.openam.aggregator.AuthorityDiscovery;
import it.infn.security.openam.aggregator.AuthorityDiscoveryFactory;

import java.security.AccessController;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AMPostAuthProcessInterface;
import com.sun.identity.authentication.spi.AuthenticationException;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.plugins.DefaultSPAttributeMapper;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;

public class AgIDAggregator
    extends DefaultSPAttributeMapper
    implements AMPostAuthProcessInterface {

    private static ThreadLocal<String> uidRegister = new ThreadLocal<String>();

    private static Debug debug = Debug.getInstance("Aggregator");

    @Override
    public void onLoginSuccess(@SuppressWarnings("rawtypes") Map requestParamsMap, HttpServletRequest request,
            HttpServletResponse response, SSOToken token)
        throws AuthenticationException {

        try {

            // String spidCode = token.getProperty(AgIDAggrConstants.UID_KEY);
            String spidCode = uidRegister.get();
            if (spidCode == null) {
                return;
            } else {
                uidRegister.remove();
            }

            String realm = DNMapper.orgNameToRealmName(token.getProperty(ISAuthConstants.ORGANIZATION));

            aggregate(realm, token.getProperty(Constants.UNIVERSAL_IDENTIFIER), spidCode, token);

        } catch (SSOException ex) {
            debug.error("SSO exception", ex);
        } catch (AggregatorException ex) {
            debug.error("Aggregation exception", ex);
        } catch (Throwable th) {
            debug.error("Generic exception", th);
        }
    }

    @Override
    public void onLoginFailure(@SuppressWarnings("rawtypes") Map requestParamsMap, HttpServletRequest request,
            HttpServletResponse response)
        throws AuthenticationException {
        // Not used
    }

    @Override
    public void onLogout(HttpServletRequest request, HttpServletResponse response, SSOToken token)
        throws AuthenticationException {
        // Not used
    }

    @Override
    public Map<String, Set<String>> getAttributes(List<Attribute> attributes, String userID, String hostEntityID,
            String remoteEntityID, String realm)
        throws SAML2Exception {

        Map<String, Set<String>> result = super.getAttributes(attributes, userID, hostEntityID, remoteEntityID, realm);
        if (result.containsKey(AgIDAggrConstants.UID_KEY)) {
            Set<String> uidSet = result.get(AgIDAggrConstants.UID_KEY);
            if (uidSet.size() != 1) {
                throw new SAML2Exception(AgIDAggrConstants.UID_KEY + " must be defined and unique");
            }
            String tmpUid = uidSet.iterator().next();
            debug.message("Set spidCode = " + tmpUid);
            uidRegister.set(tmpUid);
        }
        return result;
    }

    public static void aggregate(String realm, String uid, String spidCode, SSOToken session)
        throws AggregatorException, IdRepoException, SSOException {

        AggrConfiguration config = AggrConfigurationFactory.getInstance(realm);
        AuthorityDiscovery disco = AuthorityDiscoveryFactory.getInstance(config);
        AttributeAggregator aggregator = new AttributeAggregator(disco, config);

        Map<String, Set<String>> attributes = aggregator.getAttributes(spidCode);
        
        if (attributes.size()>0){
            HashSet<String> tmpHash = new HashSet<String>(1);
            tmpHash.add(concatValues(attributes.keySet()));
            attributes.put(AgIDAggrConstants.SPID_DICT, tmpHash);
        }
        
        if (session != null) {
            for (String kName : attributes.keySet()) {
                String tmpValue = concatValues(attributes.get(kName));
                debug.message("Found attribute " + kName + " = " + tmpValue + " for " + spidCode);
                session.setProperty(kName, tmpValue);
            }
        }

        if (uid != null && uid.trim().length() > 0) {
            try {
                HashSet<String> tmpHash = new HashSet<String>(1);
                tmpHash.add(spidCode);
                attributes.put(AgIDAggrConstants.UID_KEY, tmpHash);

                SSOToken privToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
                AMIdentity id = IdUtils.getIdentity(privToken, uid.trim());
                id.setAttributes(attributes);
                id.store();
                debug.message("Stored attributes for " + id.getName() + " on " + realm);
            } catch (Exception ex) {
                debug.error(ex.getMessage(), ex);
            }
        }

    }

    private static String concatValues(Collection<String> vItems) {
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
