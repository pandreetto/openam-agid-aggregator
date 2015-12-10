package it.infn.security.openam.aggregator;

import it.infn.security.openam.utils.SAML2ObjectBuilder;
import it.infn.security.openam.utils.SignUtils;

import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeQuery;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Subject;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.SOAPClient;
import org.opensaml.ws.soap.client.SOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.client.http.HttpSOAPRequestParameters;
import org.opensaml.ws.soap.client.http.TLSProtocolSocketFactory;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.parse.BasicParserPool;

public class AttributeAggregator {

    private static final HttpSOAPRequestParameters SOAP_PARAM = new HttpSOAPRequestParameters(
            "http://www.oasis-open.org/committees/security");

    private AuthorityDiscovery authDiscovery;

    private List<String> requiredAttributes;

    private SOAPClient soapClient;

    public AttributeAggregator(AuthorityDiscovery disco, List<String> requiredAttrs) {
        authDiscovery = disco;
        requiredAttributes = requiredAttrs;

        X509KeyManager keyManager = null;
        X509TrustManager trustManager = null;
        int conTimeout = 5000;
        int maxRequests = 50;
        int buffSize = 4096;
        soapClient = buildSOAPClient(keyManager, trustManager, conTimeout, maxRequests, buffSize);
    }

    public Map<String, String> getAttributes(String subjectID)
        throws AggregatorException {

        /*
         * TODO missing issuer
         */
        String messageIssuerId = "";

        HashMap<String, String> result = new HashMap<String, String>();

        for (URL epr : authDiscovery.getEndpoints(requiredAttributes)) {

            try {

                SOAPMessageContext msgContext = new BasicSOAPMessageContext();
                msgContext.setCommunicationProfileId(null);
                msgContext.setOutboundMessageIssuer(messageIssuerId);
                msgContext.setSOAPRequestParameters(SOAP_PARAM);

                AttributeQuery samlRequest = SAML2ObjectBuilder.buildAttributeQuery();

                samlRequest.setID(null);
                samlRequest.setIssueInstant(null);
                samlRequest.setDestination(null);
                samlRequest.setVersion(SAMLVersion.VERSION_20);

                Issuer issuer = SAML2ObjectBuilder.buildIssuer();
                issuer.setValue(messageIssuerId);
                samlRequest.setIssuer(issuer);

                Subject subject = SAML2ObjectBuilder.buildSubject();
                NameID nameId = SAML2ObjectBuilder.buildNameID();
                nameId.setFormat(null);
                nameId.setNameQualifier(null);
                nameId.setValue(subjectID);
                subject.setNameID(nameId);
                samlRequest.setSubject(subject);

                if (requiredAttributes != null && requiredAttributes.size() > 0) {
                    /*
                     * TODO implement attribute filter
                     */
                }

                SignUtils.signObject(samlRequest, null, null);

                Body body = SAML2ObjectBuilder.buildBody();
                body.getUnknownXMLObjects().add(samlRequest);
                Envelope envelope = SAML2ObjectBuilder.buildEnvelope();
                envelope.setBody(body);

                msgContext.setOutboundMessage(envelope);

                soapClient.send(epr.toString(), msgContext);

                Envelope soapResponse = (Envelope) msgContext.getInboundMessage();
                Response samlResponse = (Response) soapResponse.getBody().getOrderedChildren().get(0);
                Assertion samlAssertion = samlResponse.getAssertions().get(0);

                SignUtils.verifySignature(samlAssertion.getSignature(), null);

                List<AttributeStatement> attrStat = samlAssertion.getAttributeStatements();
                if (attrStat == null || attrStat.size() == 0) {
                    throw new AggregatorException("Missing attribute statement");
                }

                List<Attribute> attrList = attrStat.get(0).getAttributes();
                if (attrList != null) {
                    for (Attribute attribute : attrList) {
                        /*
                         * TODO implement
                         */
                    }
                }

            } catch (AggregatorException aggEx) {

                throw aggEx;

            } catch (Exception ex) {

                throw new AggregatorException(ex.getMessage());

            }
        }

        return result;
    }

    private SOAPClient buildSOAPClient(X509KeyManager keyManager, X509TrustManager trustManager, int conTimeout,
            int maxRequests, int buffSize) {

        /*
         * see org.glite.authz.pep.server.config.PEPDaemonIniConfigurationParser#processPDPConfiguration
         */
        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setContentCharSet("UTF-8");
        httpClientBuilder.setConnectionTimeout(conTimeout);
        httpClientBuilder.setMaxTotalConnections(maxRequests);
        httpClientBuilder.setMaxConnectionsPerHost(maxRequests);
        httpClientBuilder.setReceiveBufferSize(buffSize);
        httpClientBuilder.setSendBufferSize(buffSize);

        if (keyManager != null && trustManager != null) {
            TLSProtocolSocketFactory factory = new TLSProtocolSocketFactory(keyManager, trustManager);
            httpClientBuilder.setHttpsProtocolSocketFactory(factory);
        }

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(httpClientBuilder.getMaxTotalConnections());
        return new HttpSOAPClient(httpClientBuilder.buildClient(), parserPool);

    }

}