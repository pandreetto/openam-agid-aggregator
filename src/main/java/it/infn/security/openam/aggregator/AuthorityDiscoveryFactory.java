package it.infn.security.openam.aggregator;

public class AuthorityDiscoveryFactory {

    private static AuthorityDiscovery disco = null;

    public static synchronized AuthorityDiscovery getInstance(AggrConfiguration config)
        throws AggregatorException {

        if (config == null) {
            throw new AggregatorException("Missing configuration for discovery service");
        }

        if (disco == null) {
            try {
                String discoClassName = System.getProperty("it.infn.security.openam.agid.discovery.class",
                        "it.infn.security.openam.agid.AgIDAuthorityDiscoveryImpl");

                disco = (AuthorityDiscovery) Class.forName(discoClassName).newInstance();
                disco.init(config);

            } catch (Exception ex) {
                throw new AggregatorException(ex.getMessage());
            }
        }

        return disco;
    }
}