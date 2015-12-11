package it.infn.security.openam.utils;

import org.opensaml.Configuration;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeQueryBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.ws.soap.common.SOAPObjectBuilder;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.X509Certificate;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509SubjectName;
import org.opensaml.xml.signature.impl.KeyInfoBuilder;
import org.opensaml.xml.signature.impl.KeyNameBuilder;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.signature.impl.X509CertificateBuilder;
import org.opensaml.xml.signature.impl.X509DataBuilder;
import org.opensaml.xml.signature.impl.X509SubjectNameBuilder;

public class SAML2ObjectBuilder {

    private static final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();

    private static final MarshallerFactory marshallerFactory = Configuration.getMarshallerFactory();

    @SuppressWarnings("unchecked")
    private static final SOAPObjectBuilder<Envelope> envBuilder = (SOAPObjectBuilder<Envelope>) builderFactory
            .getBuilder(Envelope.DEFAULT_ELEMENT_NAME);

    @SuppressWarnings("unchecked")
    private static final SOAPObjectBuilder<Body> bodyBuilder = (SOAPObjectBuilder<Body>) builderFactory
            .getBuilder(Body.DEFAULT_ELEMENT_NAME);

    private static final AttributeQueryBuilder attrQueryBuilder = (AttributeQueryBuilder) builderFactory
            .getBuilder(AttributeQuery.DEFAULT_ELEMENT_NAME);

    private static final IssuerBuilder issuerBuilder = (IssuerBuilder) builderFactory
            .getBuilder(Issuer.DEFAULT_ELEMENT_NAME);

    private static final SubjectBuilder subjectBuilder = (SubjectBuilder) builderFactory
            .getBuilder(Subject.DEFAULT_ELEMENT_NAME);

    private static final NameIDBuilder nidBuilder = (NameIDBuilder) builderFactory
            .getBuilder(NameID.DEFAULT_ELEMENT_NAME);

    private static final KeyInfoBuilder keyInfoBuilder = (KeyInfoBuilder) builderFactory
            .getBuilder(KeyInfo.DEFAULT_ELEMENT_NAME);

    private static final KeyNameBuilder keyNameBuilder = (KeyNameBuilder) builderFactory
            .getBuilder(KeyName.DEFAULT_ELEMENT_NAME);

    private static final X509DataBuilder x509DataBuilder = (X509DataBuilder) builderFactory
            .getBuilder(X509Data.DEFAULT_ELEMENT_NAME);

    private static final X509SubjectNameBuilder x509SbjBuilder = (X509SubjectNameBuilder) builderFactory
            .getBuilder(X509SubjectName.DEFAULT_ELEMENT_NAME);

    private static final X509CertificateBuilder x509CertBuilder = (X509CertificateBuilder) builderFactory
            .getBuilder(X509Certificate.DEFAULT_ELEMENT_NAME);

    private static final SignatureBuilder signBuilder = (SignatureBuilder) builderFactory
            .getBuilder(Signature.DEFAULT_ELEMENT_NAME);

    private static final AttributeBuilder attrBuilder = (AttributeBuilder) builderFactory
            .getBuilder(Attribute.DEFAULT_ELEMENT_NAME);

    public static Marshaller getMarshaller(XMLObject xmlObj) {
        return marshallerFactory.getMarshaller(xmlObj);
    }

    public static Envelope buildEnvelope() {
        return envBuilder.buildObject();
    }

    public static Body buildBody() {
        return bodyBuilder.buildObject();
    }

    public static AttributeQuery buildAttributeQuery() {
        return attrQueryBuilder.buildObject();
    }

    public static Issuer buildIssuer() {
        return issuerBuilder.buildObject();
    }

    public static Subject buildSubject() {
        return subjectBuilder.buildObject();
    }

    public static NameID buildNameID() {
        return nidBuilder.buildObject();
    }

    public static KeyInfo buildKeyInfo() {
        return keyInfoBuilder.buildObject();
    }

    public static KeyName buildKeyName() {
        return keyNameBuilder.buildObject();
    }

    public static X509Data buildX509Data() {
        return x509DataBuilder.buildObject();
    }

    public static X509SubjectName buildX509SubjectName() {
        return x509SbjBuilder.buildObject();
    }

    public static X509Certificate buildX509Certificate() {
        return x509CertBuilder.buildObject();
    }

    public static Signature buildSignature() {
        return signBuilder.buildObject();
    }

    public static Attribute buildAttribute() {
        return attrBuilder.buildObject();
    }

}