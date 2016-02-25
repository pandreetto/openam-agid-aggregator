package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggregatorException;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public class AgIDAggrConfiguration
    implements AggrConfiguration {

    protected AgIDAggrConfiguration(String realm) throws AggregatorException {

    }

    public String getEntityID() {
        return null;
    }

    public X509KeyManager getKeyManager() {
        return null;
    }

    public X509TrustManager getTrustManager() {
        return null;
    }

    public int getConnectionTimeout() {
        return 5000;
    }

    public int getMaxRequests() {
        return 50;
    }

    public int getBufferSize() {
        return 4096;
    }

    public List<String> getRequiredAttribute()
        throws AggregatorException {
        return null;
    }

    private static Map<String, AggrConfiguration> theConfiguration = new HashMap<String, AggrConfiguration>();

    public static synchronized AggrConfiguration getInstance(String realm)
        throws AggregatorException {

        if (realm == null) {
            realm = "";
        } else {
            realm = realm.trim();
        }

        if (!theConfiguration.containsKey(realm)) {
            theConfiguration.put(realm, new AgIDAggrConfiguration(realm));
        }

        return theConfiguration.get(realm);
    }
}