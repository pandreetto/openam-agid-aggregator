package it.infn.security.openam.aggregator;

import java.util.List;

public interface AuthorityDiscovery {

    public List<AuthorityInfo> getAuthorityInfos()
        throws AggregatorException;

}