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

    protected Debug debug = Debug.getInstance("Aggregator");

    private AggrConfiguration configuration;

    private BasicParserPool parserPool;

    private CertificateFactory certFactory = null;

    public AgIDAuthorityDiscoveryImpl(AggrConfiguration config) {
        configuration = config;
        parserPool = new BasicParserPool();
        parserPool.setNamespaceAware(true);

        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (Exception ex) {
            debug.error(ex.getMessage(), ex);
        }
    }

    public List<AuthorityInfo> getAuthorityInfos()
        throws AggregatorException {

        ArrayList<AuthorityInfo> result = new ArrayList<AuthorityInfo>();

        /*
         * TODO use attribute to select authorities
         */
        // configuration.getRequiredAttribute();

        File cacheDir = new File(configuration.getMetadataCacheDir());
        for (File mdFile : cacheDir.listFiles()) {
            if (mdFile.getAbsolutePath().endsWith(".xml")) {
                AuthorityInfo authInfo = parseAuthInfo(mdFile);
                if (authInfo != null) {
                    result.add(authInfo);
                }
            }
        }

        return result;
    }

    private AuthorityInfo parseAuthInfo(File mdFile)
        throws AggregatorException {

        BufferedReader reader = null;
        try {

            reader = new BufferedReader(new FileReader(mdFile));
            Document docRoot = parserPool.parse(reader);
            Element mdElem = docRoot.getDocumentElement();

            Unmarshaller unmarshaller = SAML2ObjectBuilder.getUnmarshaller(mdElem);
            EntityDescriptor entDescr = (EntityDescriptor) unmarshaller.unmarshall(mdElem);

            AuthorityInfo result = new AuthorityInfo(entDescr.getID());

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

}