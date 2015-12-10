package it.infn.security.openam.aggregator;

import java.net.URL;
import java.util.List;

public interface AuthorityDiscovery {

    public List<URL> getEndpoints(List<String> requiredAttributes)
        throws AggregatorException;

}