package it.infn.security.openam.aggregator;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Set;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

public interface AggrConfiguration {

    public void init(String realm)
        throws AggregatorException;

    public String getEntityID()
        throws AggregatorException;

    public X509KeyManager getKeyManager()
        throws AggregatorException;

    public X509TrustManager getTrustManager()
        throws AggregatorException;

    public int getConnectionTimeout()
        throws AggregatorException;

    public int getMaxRequests()
        throws AggregatorException;

    public int getBufferSize()
        throws AggregatorException;

    public Set<String> getRequiredAttributes()
        throws AggregatorException;

    public X509Certificate getServiceCertificate()
        throws AggregatorException;

    public PrivateKey getServicePrivateKey()
        throws AggregatorException;

    public String getMetadataCacheDir()
        throws AggregatorException;

    public int getMetadataValidity()
        throws AggregatorException;

}