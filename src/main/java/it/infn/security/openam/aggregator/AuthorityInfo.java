package it.infn.security.openam.aggregator;

import java.net.URL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class AuthorityInfo {

    private String entityID;

    private URL authURL;

    private List<X509Certificate> certs;

    public AuthorityInfo(String id) {
        entityID = id;
        certs = new ArrayList<X509Certificate>(1);
    }

    public String getEntityID() {
        return entityID;
    }

    public void setURL(URL url) {
        authURL = url;
    }

    public URL getURL() {
        return authURL;
    }

    public void addCertificate(X509Certificate cert) {
        certs.add(cert);
    }

    public List<X509Certificate> getCertificates() {
        return certs;
    }
}