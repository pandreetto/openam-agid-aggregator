package it.infn.security.openam.utils;

import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.codec.binary.Base64;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.opensaml.common.impl.SAMLObjectContentReference;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.ContentReference;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.KeyName;
import org.opensaml.xml.signature.SignableXMLObject;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.X509Data;
import org.opensaml.xml.signature.X509SubjectName;
import org.opensaml.xml.validation.ValidationException;

import com.sun.identity.shared.debug.Debug;

public class SignUtils {

    private static final Debug debug = Debug.getInstance("Aggregator");

    private static final Base64 base64Enc = new Base64(64, new byte[] { '\n' });

    public static KeyInfo buildKeyInfo(X509Certificate signCert)
        throws CertificateException {

        KeyInfo keyInfo = SAML2ObjectBuilder.buildKeyInfo();
        KeyName keyName = SAML2ObjectBuilder.buildKeyName();
        X509Data x509Data = SAML2ObjectBuilder.buildX509Data();
        X509SubjectName x509Sbj = SAML2ObjectBuilder.buildX509SubjectName();

        org.opensaml.xml.signature.X509Certificate x509Cert = SAML2ObjectBuilder.buildX509Certificate();
        keyName.setValue(signCert.getSubjectDN().getName());
        x509Sbj.setValue(signCert.getSubjectDN().getName());
        x509Data.getX509SubjectNames().add(x509Sbj);
        byte[] certEncoded = signCert.getEncoded();
        x509Cert.setValue(base64Enc.encodeToString(certEncoded));
        x509Data.getX509Certificates().add(x509Cert);

        keyInfo.getKeyNames().add(keyName);
        keyInfo.getX509Datas().add(x509Data);

        return keyInfo;
    }

    public static void signObject(SignableXMLObject object, X509Certificate srvCert, PrivateKey srvKey)
        throws SignatureException, MarshallingException, CertificateException {

        Credential credential = SecurityHelper.getSimpleCredential(srvCert, srvKey);

        Signature objSignature = SAML2ObjectBuilder.buildSignature();
        objSignature.setSigningCredential(credential);
        objSignature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        objSignature.setSignatureAlgorithm(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
        objSignature.setKeyInfo(SignUtils.buildKeyInfo(srvCert));

        object.setSignature(objSignature);

        for (ContentReference refItem : objSignature.getContentReferences()) {
            if (refItem instanceof SAMLObjectContentReference) {
                SAMLObjectContentReference tmpRef = (SAMLObjectContentReference) refItem;
                tmpRef.setDigestAlgorithm(MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512);
            }
        }

        Marshaller marshaller = SAML2ObjectBuilder.getMarshaller(object);
        marshaller.marshall(object);

        Signer.signObject(objSignature);
    }

    public static void verifySignature(Signature signature, X509Certificate subjectCertificate)
        throws SecurityException, CertificateException, ValidationException {

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(signature);

        if (subjectCertificate == null) {
            throw new SecurityException("Cannot retrieve peer certificate");
        }

        Credential peerCredential = SecurityHelper.getSimpleCredential(subjectCertificate, null);

        SignatureValidator signatureValidator = new SignatureValidator(peerCredential);
        signatureValidator.validate(signature);
        debug.message("Signature verified for " + subjectCertificate.getSubjectX500Principal().getName());

    }

}