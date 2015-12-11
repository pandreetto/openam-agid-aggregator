package it.infn.security.openam.aggregator;

import java.util.List;

public interface AuthorityDiscovery {

    public List<AuthorityInfo> getAuthorityInfos(List<String> requiredAttributes)
        throws AggregatorException;

}