package it.infn.security.openam.agid;

import java.net.URL;
import java.util.List;

import it.infn.security.openam.aggregator.AggregatorException;
import it.infn.security.openam.aggregator.AuthorityDiscovery;

public class AgIDAuthorityDiscoveryImpl
    implements AuthorityDiscovery {

    public AgIDAuthorityDiscoveryImpl() {

    }

    public List<URL> getEndpoints()
        throws AggregatorException {
        return null;
    }

}