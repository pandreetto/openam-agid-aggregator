package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggregatorException;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import com.iplanet.am.util.SystemProperties;

public class AgIDAggrConfiguration
    implements AggrConfiguration {

    private static final String ATTRIBUTES_LIST = "it.infn.security.openam.agid.required.attributes";

    private static final String ENTITY_ID = "it.infn.security.openam.agid.entity.id";

    private static final String KEYMAN_FILE = "it.infn.security.openam.agid.key.manager.file";

    private static final String KEYMAN_TYPE = "it.infn.security.openam.agid.key.manager.type";

    private static final String KEYMAN_PWD = "it.infn.security.openam.agid.key.manager.password";

    private static final String KEYMAN_ALIAS = "it.infn.security.openam.agid.key.manager.alias";

    private static final String TRUSTMAN_FILE = "it.infn.security.openam.agid.trust.manager.file";

    private static final String TRUSTMAN_TYPE = "it.infn.security.openam.agid.trust.manager.type";

    private static final String TRUSTMAN_PWD = "it.infn.security.openam.agid.trust.manager.password";

    private static final String METADATA_DIR = "it.infn.security.openam.agid.metadata.cache";

    private static final String METADATA_VALID = "it.infn.security.openam.agid.metadata.valid.until";

    private static final String CONN_TIMEOUT = "it.infn.security.openam.agid.connection.timeout";

    private static final String MAX_REQUESTS = "it.infn.security.openam.agid.max.requests";

    private static final String BUFFER_SIZE = "it.infn.security.openam.agid.buffer.size";

    private X509KeyManager keyManager = null;

    private X509TrustManager trustManager = null;

    private X509Certificate serviceCert = null;

    private PrivateKey serviceKey = null;

    /*
     * TODO implement configuration per realm
     */

    public void init(String realm)
        throws AggregatorException {

        FileInputStream fis1 = null;
        try {

            String ksType = SystemProperties.get(KEYMAN_TYPE, KeyStore.getDefaultType());
            KeyStore ks = KeyStore.getInstance(ksType);
            char[] password = SystemProperties.get(KEYMAN_PWD, "").toCharArray();
            fis1 = new FileInputStream(SystemProperties.get(KEYMAN_FILE));
            ks.load(fis1, password);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, password);

            for (KeyManager kItem : kmf.getKeyManagers()) {
                if (kItem instanceof X509KeyManager) {
                    keyManager = (X509KeyManager) kItem;
                    break;
                }
            }

        } catch (Throwable th) {
            throw new AggregatorException("Cannot load key manager");
        } finally {
            if (fis1 != null) {
                try {
                    fis1.close();
                } catch (Exception ex) {
                }
            }
        }

        if (keyManager == null) {
            throw new AggregatorException("Missing key manager");
        }

        FileInputStream fis2 = null;
        try {

            String ksType = SystemProperties.get(TRUSTMAN_TYPE, KeyStore.getDefaultType());
            KeyStore ks = KeyStore.getInstance(ksType);
            char[] password = SystemProperties.get(TRUSTMAN_PWD, "").toCharArray();
            fis2 = new FileInputStream(SystemProperties.get(TRUSTMAN_FILE));
            ks.load(fis2, password);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);

            for (TrustManager tItem : tmf.getTrustManagers()) {
                if (tItem instanceof X509TrustManager) {
                    trustManager = (X509TrustManager) tItem;
                    break;
                }
            }

        } catch (Throwable th) {
            throw new AggregatorException("Cannot load trust manager");
        } finally {
            if (fis2 != null) {
                try {
                    fis2.close();
                } catch (Exception ex) {
                }
            }
        }

        if (trustManager == null) {
            throw new AggregatorException("Missing trust manager");
        }

        String keyAlias = SystemProperties.get(KEYMAN_ALIAS);

        serviceKey = keyManager.getPrivateKey(keyAlias);
        if (serviceKey == null)
            throw new AggregatorException("Cannot extract private key from key manager");

        X509Certificate[] certChain = keyManager.getCertificateChain(keyAlias);
        if (certChain == null)
            throw new AggregatorException("Cannot extract certificates from key manager");
        serviceCert = certChain[0];
    }

    public String getEntityID() {
        return SystemProperties.get(ENTITY_ID);
    }

    public X509KeyManager getKeyManager() {
        return keyManager;
    }

    public X509TrustManager getTrustManager() {
        return trustManager;
    }

    public int getConnectionTimeout() {
        try {
            return Integer.parseInt(SystemProperties.get(CONN_TIMEOUT, "5000"));
        } catch (Throwable th) {
            return 5000;
        }
    }

    public int getMaxRequests() {
        try {
            return Integer.parseInt(SystemProperties.get(MAX_REQUESTS, "50"));
        } catch (Throwable th) {
            return 50;
        }
    }

    public int getBufferSize() {
        try {
            return Integer.parseInt(SystemProperties.get(BUFFER_SIZE, "4096"));
        } catch (Throwable th) {
            return 4096;
        }
    }

    public Set<String> getRequiredAttributes()
        throws AggregatorException {

        /*
         * TODO get attribute from internal metadata
         */

        String[] attrs = SystemProperties.get(ATTRIBUTES_LIST).split(":");

        HashSet<String> result = new HashSet<String>(attrs.length);
        for (String tmps : attrs) {
            result.add(tmps.trim());
        }

        return result;
    }

    public X509Certificate getServiceCertificate()
        throws AggregatorException {
        return serviceCert;
    }

    public PrivateKey getServicePrivateKey()
        throws AggregatorException {
        return serviceKey;
    }

    public String getMetadataCacheDir()
        throws AggregatorException {
        return SystemProperties.get(METADATA_DIR);
    }

    public int getMetadataValidity()
        throws AggregatorException {
        try {
            return Integer.parseInt(SystemProperties.get(METADATA_VALID, "5"));
        } catch (Throwable th) {
            return 5;
        }
    }

}