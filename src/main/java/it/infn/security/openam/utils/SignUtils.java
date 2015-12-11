package it.infn.security.openam.utils;

import java.io.ByteArrayInputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import javax.security.auth.Subject;

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

public class SignUtils {

    private static final Logger logger = Logger.getLogger(SignUtils.class.getName());

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

    private static void validateCertificate(X509Certificate certificate)
        throws CertificateException {
    }

    public static X509Certificate extractCertificate(Signature signature)
        throws CertificateException {

        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo == null) {
            return null;
        }

        List<X509Data> x509Datas = keyInfo.getX509Datas();
        if (x509Datas != null) {
            for (X509Data tmpData : x509Datas) {
                List<org.opensaml.xml.signature.X509Certificate> tmpCerts = tmpData.getX509Certificates();
                if (tmpCerts != null) {
                    /*
                     * TODO assume the user cert is the first of the chain
                     */
                    String b64cert = tmpCerts.get(0).getValue();
                    ByteArrayInputStream bIn = new ByteArrayInputStream(Base64.decodeBase64(b64cert));
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    X509Certificate result = (X509Certificate) cf.generateCertificate(bIn);
                    validateCertificate(result);
                    return result;
                }
            }
        }
        return null;
    }

    public static void signObject(SignableXMLObject object)
        throws SignatureException, MarshallingException, CertificateException {

        /*
         * TODO missing credential
         */
        X509Certificate srvCert = null;
        PrivateKey srvKey = null;
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

    public static void verifySignature(Signature signature, Subject requester)
        throws SecurityException, CertificateException, ValidationException {

        /*
         * TODO check digest algorithm (cannot retrieve algorithm from signature
         */

        SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
        profileValidator.validate(signature);

        X509Certificate subjectCertificate = null;
        Set<X509Certificate[]> allChain = requester.getPublicCredentials(X509Certificate[].class);
        for (X509Certificate[] peerChain : allChain) {
            subjectCertificate = peerChain[0];
        }

        if (subjectCertificate == null) {
            subjectCertificate = extractCertificate(signature);
        }

        if (subjectCertificate == null) {
            throw new SecurityException("Cannot retrieve peer certificate");
        }

        Credential peerCredential = SecurityHelper.getSimpleCredential(subjectCertificate, null);

        SignatureValidator signatureValidator = new SignatureValidator(peerCredential);
        signatureValidator.validate(signature);
        logger.fine("Signature verified for " + subjectCertificate.getSubjectX500Principal().getName());

    }

    public static String extractDigestAlgorithm(Signature signature) {
        List<ContentReference> refList = signature.getContentReferences();
        /*
         * Use the first algorithm found
         */
        if (refList.size() > 0) {
            return ((SAMLObjectContentReference) refList.get(0)).getDigestAlgorithm();
        }
        return null;
    }

}