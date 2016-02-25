package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggregatorException;
import it.infn.security.openam.aggregator.AuthorityDiscovery;
import it.infn.security.openam.aggregator.AuthorityInfo;

import java.util.List;

import com.iplanet.am.util.SystemProperties;

public class AgIDAuthorityDiscoveryImpl
    implements AuthorityDiscovery {

    private static final String TEST_AA_URL_TAG = "it.infn.security.openam.agid.test.attr.auth";
    
    private AggrConfiguration configuration;

    public AgIDAuthorityDiscoveryImpl(AggrConfiguration config) {
        configuration = config;
    }

    public List<AuthorityInfo> getAuthorityInfos()
        throws AggregatorException {

        /*
         * TODO use attribute to select authorities
         */
        configuration.getRequiredAttribute();
        
        /*
         * TODO use static authority just for test
         */
        String authURL = SystemProperties.get(TEST_AA_URL_TAG);
        
        /*
         * TODO use cache
         */

        return null;
    }

}