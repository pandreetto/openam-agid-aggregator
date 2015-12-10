package it.infn.security.openam.aggregator;

import java.util.Map;

public class AttributeAggregator {

    private AuthorityDiscovery authDiscovery;

    public AttributeAggregator(AuthorityDiscovery disco) {
        authDiscovery = disco;
    }

    public Map<String, String> getAttributes()
        throws AggregatorException {
        return null;
    }
}