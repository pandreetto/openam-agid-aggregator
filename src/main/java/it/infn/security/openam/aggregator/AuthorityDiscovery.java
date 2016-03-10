package it.infn.security.openam.aggregator;

import java.util.List;

public interface AuthorityDiscovery {

    public void init(AggrConfiguration config)
        throws AggregatorException;

    public List<AuthorityInfo> getAuthorityInfos()
        throws AggregatorException;

}