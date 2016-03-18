package it.infn.security.openam.agid;

import it.infn.security.openam.aggregator.AggrConfiguration;
import it.infn.security.openam.aggregator.AggregatorException;
import it.infn.security.openam.aggregator.AuthorityDiscovery;
import it.infn.security.openam.aggregator.AuthorityInfo;
import it.infn.security.openam.utils.SAML2ObjectBuilder;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileReader;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.PriorityQueue;
import java.util.Set;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.metadata.AttributeAuthorityDescriptor;
import org.opensaml.saml2.metadata.AttributeService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import com.sun.identity.shared.debug.Debug;

public class AgIDAuthorityDiscoveryImpl
    implements AuthorityDiscovery {

    private static final String REQ_PROTO = "urn:oasis:names:tc:SAML:2.0:protocol";

    private static PriorityQueue<AuthorityInfoWrapper> authCache = new PriorityQueue<AuthorityInfoWrapper>();

    protected Debug debug = Debug.getInstance("Aggregator");

    private AggrConfiguration configuration;

    private BasicParserPool parserPool;

    private CertificateFactory certFactory = null;

    public void init(AggrConfiguration config)
        throws AggregatorException {
        configuration = config;
        parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);

        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (Exception ex) {
            debug.error(ex.getMessage(), ex);
            throw new AggregatorException("Cannot initialize discovery service");
        }
    }

    public List<AuthorityInfo> getAuthorityInfos()
        throws AggregatorException {

        synchronized (authCache) {

            long now = System.currentTimeMillis();
            AuthorityInfoWrapper head = authCache.peek();

            if (head == null) {

                rebuildCache();

            } else if (now >= head.authInfo.getValidUntil()) {

                head = authCache.poll();
                AuthorityInfo authInfo = parseAuthInfo(new File(head.fileName));
                if (authInfo == null || authInfo.getValidUntil() <= now) {
                    rebuildCache();
                } else {
                    authCache.offer(new AuthorityInfoWrapper(head.fileName, authInfo));
                }
            }
        }

        ArrayList<AuthorityInfo> result = new ArrayList<AuthorityInfo>(authCache.size());
        for (AuthorityInfoWrapper infoWrapper : authCache) {
            result.add(infoWrapper.authInfo);
        }

        return result;
    }

    private void rebuildCache()
        throws AggregatorException {

        debug.message("Triggered cache renewal");

        /*
         * TODO improve cache renewal
         */
        authCache.clear();

        File cacheDir = new File(configuration.getMetadataCacheDir());
        for (File mdFile : cacheDir.listFiles()) {
            if (mdFile.getAbsolutePath().endsWith(".xml")) {
                AuthorityInfo authInfo = parseAuthInfo(mdFile);
                if (authInfo == null) {
                    continue;
                } else if (authInfo.getValidUntil() < System.currentTimeMillis()) {
                    debug.error("Metadata expired in " + mdFile.getAbsolutePath());
                } else {
                    authCache.offer(new AuthorityInfoWrapper(mdFile.getAbsolutePath(), authInfo));
                }
            }
        }

    }

    private AuthorityInfo parseAuthInfo(File mdFile)
        throws AggregatorException {

        Set<String> reqAttributes = configuration.getRequiredAttributes();

        BufferedReader reader = null;
        try {

            reader = new BufferedReader(new FileReader(mdFile));
            Document docRoot = parserPool.parse(reader);
            Element mdElem = docRoot.getDocumentElement();

            Unmarshaller unmarshaller = SAML2ObjectBuilder.getUnmarshaller(mdElem);
            EntityDescriptor entDescr = (EntityDescriptor) unmarshaller.unmarshall(mdElem);

            /*
             * TODO verify metadata signature against AgID certificate
             */

            AuthorityInfo result = new AuthorityInfo(entDescr.getEntityID());

            AttributeAuthorityDescriptor aaDescr = entDescr.getAttributeAuthorityDescriptor(REQ_PROTO);
            for (AttributeService aaService : aaDescr.getAttributeServices()) {
                URL location = new URL(aaService.getLocation());
                result.setURL(location);
            }

            for (KeyDescriptor kDescr : aaDescr.getKeyDescriptors()) {
                KeyInfo kInfo = kDescr.getKeyInfo();
                for (X509Data x509Data : kInfo.getX509Datas()) {
                    for (X509Certificate xCert : x509Data.getX509Certificates()) {
                        Certificate tmpCert = parsePEMCert(xCert.getValue());
                        if (tmpCert != null) {
                            result.addCertificate((java.security.cert.X509Certificate) tmpCert);
                        }

                    }
                }
            }

            for (Attribute pubAttr : aaDescr.getAttributes()) {
                String attrName = pubAttr.getName();
                if (reqAttributes.contains(pubAttr)) {
                    result.addRequiredAttribute(attrName);
                }
            }

            DateTime validUntil = entDescr.getValidUntil();
            if (validUntil == null) {
                int defValidity = configuration.getMetadataValidity();
                validUntil = DateTime.now().plusDays(defValidity);
            }
            result.setValidUntil(validUntil.getMillis());

            return result;

        } catch (Throwable th) {
            debug.error(th.getMessage(), th);
            if (reader != null) {
                try {
                    reader.close();
                } catch (Exception ex) {
                    debug.error(ex.getMessage(), ex);
                }
            }
        }

        return null;
    }

    private Certificate parsePEMCert(String pemStr) {
        try {
            StringBuffer buff = new StringBuffer("-----BEGIN CERTIFICATE-----\n");
            buff.append(pemStr.trim()).append("\n-----END CERTIFICATE-----");
            ByteArrayInputStream bStream = new ByteArrayInputStream(buff.toString().getBytes());
            Certificate result = certFactory.generateCertificate(bStream);
            bStream.close();

            return result;

        } catch (Exception ex) {
            debug.error(ex.getMessage(), ex);
        }

        return null;
    }

    public class AuthorityInfoWrapper
        implements Comparable<AuthorityInfoWrapper> {

        public String fileName;

        public AuthorityInfo authInfo;

        public AuthorityInfoWrapper(String fName, AuthorityInfo aInfo) {
            fileName = fName;
            authInfo = aInfo;
        }

        public int compareTo(AuthorityInfoWrapper w1) {
            if (authInfo.getValidUntil() < w1.authInfo.getValidUntil())
                return -1;
            if (authInfo.getValidUntil() > w1.authInfo.getValidUntil())
                return 1;
            return 0;
        }

    }

}