package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggregatorException;
import it.infn.security.openam.aggregator.AuthorityDiscovery;
import it.infn.security.openam.aggregator.AuthorityInfo;

import java.util.List;

public class AgIDAuthorityDiscoveryImpl
    implements AuthorityDiscovery {

    public AgIDAuthorityDiscoveryImpl() {

    }

    public List<AuthorityInfo> getAuthorityInfos(List<String> requiredAttributes)
        throws AggregatorException {
        return null;
    }

}