package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggregatorException;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileReader;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import com.iplanet.am.util.SystemProperties;
import com.sun.identity.shared.debug.Debug;

public class AgIDAggrConfiguration
    implements AggrConfiguration {

    private static final String CONF_FILE = "it.infn.security.openam.agid.configuration.file";

    private static final String ATTRIBUTES_LIST = "required.attributes";

    private static final String ENTITY_ID = "entity.id";

    private static final String KEYMAN_FILE = "key.manager.file";

    private static final String KEYMAN_TYPE = "key.manager.type";

    private static final String KEYMAN_PWD = "key.manager.password";

    private static final String KEY_ALIAS = "key.alias";

    private static final String KEY_PWD = "key.passphrase";

    private static final String TRUSTMAN_FILE = "trust.manager.file";

    private static final String TRUSTMAN_TYPE = "trust.manager.type";

    private static final String TRUSTMAN_PWD = "trust.manager.password";

    private static final String METADATA_DIR = "metadata.cache";

    private static final String METADATA_VALID = "metadata.valid.until";

    private static final String CONN_TIMEOUT = "connection.timeout";

    private static final String MAX_REQUESTS = "max.requests";

    private static final String BUFFER_SIZE = "buffer.size";

    private String entityId;

    private String metadataDir;

    private String attrListStr;

    private int connTimeout;

    private int maxRequests;

    private int bufferSize;

    private int mdValid;

    private X509KeyManager keyManager = null;

    private X509TrustManager trustManager = null;

    private X509Certificate serviceCert = null;

    private PrivateKey serviceKey = null;

    protected Debug debug = Debug.getInstance("Aggregator");

    public void init(String realm)
        throws AggregatorException {

        realm = realm == null ? "" : realm.trim();
        String prefix = realm.length() == 0 ? "root." : "root" + realm.replace("/", ".");

        BufferedReader reader = null;
        String keyManagerFile = null;
        String keyManagerType = null;
        String keyManagerPwd = null;
        String keyAlias = null;
        String keyPwd = null;
        String trustManagerFile = null;
        String trustManagerType = null;
        String trustManagerPwd = null;
        try {

            String confFilename = SystemProperties.get(CONF_FILE, "/etc/openam-agid-aggregator/aggregator.conf");
            reader = new BufferedReader(new FileReader(confFilename));

            Properties props = new Properties();
            props.load(reader);

            entityId = props.getProperty(prefix + ENTITY_ID);
            keyManagerFile = props.getProperty(prefix + KEYMAN_FILE);
            keyManagerType = props.getProperty(prefix + KEYMAN_TYPE, KeyStore.getDefaultType());
            keyManagerPwd = props.getProperty(prefix + KEYMAN_PWD, "");
            keyAlias = props.getProperty(prefix + KEY_ALIAS);
            keyPwd = props.getProperty(prefix + KEY_PWD);
            trustManagerFile = props.getProperty(prefix + TRUSTMAN_FILE);
            trustManagerType = props.getProperty(prefix + TRUSTMAN_TYPE, KeyStore.getDefaultType());
            trustManagerPwd = props.getProperty(prefix + TRUSTMAN_PWD, "");
            metadataDir = props.getProperty(prefix + METADATA_DIR);
            try {
                mdValid = Integer.parseInt(props.getProperty(prefix + METADATA_VALID));
            } catch (Exception ex) {
                debug.warning("Wrong value for " + prefix + METADATA_VALID + ", default used");
                mdValid = 5;
            }
            try {
                connTimeout = Integer.parseInt(props.getProperty(prefix + CONN_TIMEOUT));
            } catch (Exception ex) {
                debug.warning("Wrong value for " + prefix + CONN_TIMEOUT + ", default used");
                connTimeout = 5000;
            }
            try {
                maxRequests = Integer.parseInt(props.getProperty(prefix + MAX_REQUESTS));
            } catch (Exception ex) {
                debug.warning("Wrong value for " + prefix + MAX_REQUESTS + ", default used");
                maxRequests = 50;
            }
            try {
                bufferSize = Integer.parseInt(props.getProperty(prefix + BUFFER_SIZE));
            } catch (Exception ex) {
                debug.warning("Wrong value for " + prefix + BUFFER_SIZE + ", default used");
                bufferSize = 4096;
            }

            attrListStr = props.getProperty(prefix + ATTRIBUTES_LIST, "");

        } catch (Throwable th) {

            debug.error(th.getMessage(), th);
            throw new AggregatorException("Cannot load configuration for " + realm);

        } finally {

            if (reader != null) {
                try {
                    reader.close();
                } catch (Throwable th) {
                    debug.error(th.getMessage(), th);
                }
            }
        }

        FileInputStream fis1 = null;
        try {

            KeyStore ks = KeyStore.getInstance(keyManagerType);
            char[] password = keyManagerPwd.toCharArray();
            fis1 = new FileInputStream(keyManagerFile);
            ks.load(fis1, password);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, keyPwd != null ? keyPwd.toCharArray() : null);

            for (KeyManager kItem : kmf.getKeyManagers()) {
                if (kItem instanceof X509KeyManager) {
                    keyManager = (X509KeyManager) kItem;
                    break;
                }
            }

        } catch (Throwable th) {
            debug.error(th.getMessage(), th);
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

            KeyStore ks = KeyStore.getInstance(trustManagerType);
            char[] password = trustManagerPwd.toCharArray();
            fis2 = new FileInputStream(trustManagerFile);
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
            debug.error(th.getMessage(), th);
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

        serviceKey = keyManager.getPrivateKey(keyAlias);
        if (serviceKey == null)
            throw new AggregatorException("Cannot extract private key from key manager");

        X509Certificate[] certChain = keyManager.getCertificateChain(keyAlias);
        if (certChain == null)
            throw new AggregatorException("Cannot extract certificates from key manager");
        serviceCert = certChain[0];
    }

    public String getEntityID() {
        return entityId;
    }

    public X509KeyManager getKeyManager() {
        return keyManager;
    }

    public X509TrustManager getTrustManager() {
        return trustManager;
    }

    public int getConnectionTimeout() {
        return connTimeout;
    }

    public int getMaxRequests() {
        return maxRequests;
    }

    public int getBufferSize() {
        return bufferSize;
    }

    public Set<String> getRequiredAttributes()
        throws AggregatorException {

        /*
         * TODO get attribute from internal metadata
         */

        String[] attrs = attrListStr.split(":");

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
        return metadataDir;
    }

    public int getMetadataValidity()
        throws AggregatorException {
        return mdValid;
    }

}