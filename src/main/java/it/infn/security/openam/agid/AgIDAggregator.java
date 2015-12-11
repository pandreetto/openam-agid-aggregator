package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggregatorException;
import it.infn.security.openam.aggregator.AttributeAggregator;

import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.sun.identity.shared.debug.Debug;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.authentication.spi.AMPostAuthProcessInterface;
import com.sun.identity.authentication.spi.AuthenticationException;

public class AgIDAggregator
    implements AMPostAuthProcessInterface {

    protected Debug debug = Debug.getInstance("/tmp/aggregator.log");

    public void onLoginSuccess(@SuppressWarnings("rawtypes")
    Map requestParamsMap, HttpServletRequest request, HttpServletResponse response, SSOToken token)
        throws AuthenticationException {

        try {

            AgIDAuthorityDiscoveryImpl disco = new AgIDAuthorityDiscoveryImpl();
            AttributeAggregator aggregator = new AttributeAggregator(disco, null);

            /*
             * TODO verify
             */
            String spidCode = token.getProperty("spidCode");

            Map<String, List<String>> attributes = aggregator.getAttributes(spidCode);
            for (String kName : attributes.keySet()) {
                for (String value : attributes.get(kName)) {
                    /*
                     * TODO check multivalue property
                     */
                    token.setProperty(kName, value);
                }
            }

        } catch (SSOException ex) {
            /*
             * TODO implement
             */
        } catch (AggregatorException ex) {
            /*
             * TODO implement
             */
        }
    }

    public void onLoginFailure(@SuppressWarnings("rawtypes")
    Map requestParamsMap, HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {
        // Not used
    }

    public void onLogout(HttpServletRequest request, HttpServletResponse response, SSOToken token)
        throws AuthenticationException {
        // Not used
    }
}
