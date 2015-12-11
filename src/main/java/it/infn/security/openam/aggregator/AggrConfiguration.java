package it.infn.security.openam.aggregator;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public class AggrConfiguration {

    protected AggrConfiguration()
        throws AggregatorException {

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

    private static AggrConfiguration theConfiguration = null;

    public static AggrConfiguration getInstance()
        throws AggregatorException {

        if (theConfiguration == null) {
            synchronized (AggrConfiguration.class) {
                if (theConfiguration == null) {
                    theConfiguration = new AggrConfiguration();
                }
            }
        }

        return theConfiguration;
    }
}