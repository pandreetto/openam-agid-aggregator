package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggrConfigurationFactory;
import it.infn.security.openam.aggregator.AggregatorException;
import it.infn.security.openam.aggregator.AttributeAggregator;
import it.infn.security.openam.aggregator.AuthorityDiscovery;
import it.infn.security.openam.aggregator.AuthorityDiscoveryFactory;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AMPostAuthProcessInterface;
import com.sun.identity.authentication.spi.AuthenticationException;
import com.sun.identity.plugin.session.SessionProvider;
import com.sun.identity.saml2.assertion.Attribute;
import com.sun.identity.saml2.common.SAML2Exception;
import com.sun.identity.saml2.plugins.DefaultSPAttributeMapper;
import com.sun.identity.shared.debug.Debug;

public class AgIDAggregator
    extends DefaultSPAttributeMapper
    implements AMPostAuthProcessInterface {

    private static String UID_KEY = "spidCode";

    private static ThreadLocal<String> uidRegister = new ThreadLocal<String>();

    protected Debug debug = Debug.getInstance("Aggregator");

    @Override
    public void onLoginSuccess(@SuppressWarnings("rawtypes") Map requestParamsMap, HttpServletRequest request,
            HttpServletResponse response, SSOToken token)
        throws AuthenticationException {

        try {

            // String spidCode = token.getProperty(UID_KEY);
            String spidCode = uidRegister.get();
            if (spidCode == null) {
                return;
            } else {
                uidRegister.remove();
            }

            String realm = token.getProperty(SessionProvider.REALM);

            AggrConfiguration config = AggrConfigurationFactory.getInstance(realm);
            AuthorityDiscovery disco = AuthorityDiscoveryFactory.getInstance(config);
            AttributeAggregator aggregator = new AttributeAggregator(disco, config);

            Map<String, List<String>> attributes = aggregator.getAttributes(spidCode);
            for (String kName : attributes.keySet()) {
                String tmpValue = concatValues(attributes.get(kName));
                debug.message("Found attribute " + kName + " = " + tmpValue);
                token.setProperty(kName, tmpValue);
            }

            token.setProperty("spid_dict", concatValues(attributes.keySet()));

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
        if (result.containsKey(UID_KEY)) {
            Set<String> uidSet = result.get(UID_KEY);
            if (uidSet.size() != 1) {
                throw new SAML2Exception(UID_KEY + " must be defined and unique");
            }
            String tmpUid = uidSet.iterator().next();
            debug.message("Set spidCode = " + tmpUid);
            uidRegister.set(tmpUid);
        }
        return result;
    }

    private String concatValues(Collection<String> vItems) {
        /*
         * TODO check length and thow exception
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
