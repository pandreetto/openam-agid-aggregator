package it.infn.security.openam.aggregator;

import it.infn.security.openam.utils.SAML2ObjectBuilder;
import it.infn.security.openam.utils.SignUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

import org.joda.time.DateTime;
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
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;

public class AttributeAggregator {

    private static final HttpSOAPRequestParameters SOAP_PARAM = new HttpSOAPRequestParameters(
            "http://www.oasis-open.org/committees/security");

    private AuthorityDiscovery authDiscovery;

    private AggrConfiguration configuration;

    private SOAPClient soapClient;

    public AttributeAggregator(AuthorityDiscovery disco, AggrConfiguration config) throws AggregatorException {
        authDiscovery = disco;
        configuration = config;
        soapClient = buildSOAPClient();
    }

    public Map<String, List<String>> getAttributes(String subjectID)
        throws AggregatorException {

        List<String> requiredAttributes = configuration.getRequiredAttribute();
        String entityId = configuration.getEntityID();

        HashMap<String, List<String>> result = new HashMap<String, List<String>>();

        for (AuthorityInfo info : authDiscovery.getAuthorityInfos()) {

            try {

                String requestId = "_" + UUID.randomUUID().toString();

                SOAPMessageContext msgContext = new BasicSOAPMessageContext();
                msgContext.setCommunicationProfileId("urn:oasis:names:tc:SAML:2.0:profiles:query");
                msgContext.setOutboundMessageIssuer(entityId);
                msgContext.setSOAPRequestParameters(SOAP_PARAM);

                AttributeQuery samlRequest = SAML2ObjectBuilder.buildAttributeQuery();

                samlRequest.setID(requestId);
                samlRequest.setIssueInstant(new DateTime());
                samlRequest.setDestination(info.getURL().toString());
                samlRequest.setVersion(SAMLVersion.VERSION_20);

                Issuer issuer = SAML2ObjectBuilder.buildIssuer();
                issuer.setValue(entityId);
                samlRequest.setIssuer(issuer);

                Subject subject = SAML2ObjectBuilder.buildSubject();
                NameID nameId = SAML2ObjectBuilder.buildNameID();
                nameId.setFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
                nameId.setNameQualifier(info.getURL().toString());
                nameId.setValue(subjectID);
                subject.setNameID(nameId);
                samlRequest.setSubject(subject);

                if (requiredAttributes != null && requiredAttributes.size() > 0) {
                    for (String reqAttr : requiredAttributes) {
                        Attribute attribute = SAML2ObjectBuilder.buildAttribute();
                        attribute.setName(reqAttr);
                        attribute.setNameFormat(Attribute.BASIC);
                        samlRequest.getAttributes().add(attribute);
                    }
                }

                SignUtils.signObject(samlRequest, null, null);

                Body body = SAML2ObjectBuilder.buildBody();
                body.getUnknownXMLObjects().add(samlRequest);
                Envelope envelope = SAML2ObjectBuilder.buildEnvelope();
                envelope.setBody(body);

                msgContext.setOutboundMessage(envelope);

                soapClient.send(info.getURL().toString(), msgContext);

                Envelope soapResponse = (Envelope) msgContext.getInboundMessage();
                Response samlResponse = (Response) soapResponse.getBody().getOrderedChildren().get(0);
                Assertion samlAssertion = samlResponse.getAssertions().get(0);

                if (info.getCertificates().size() == 0) {
                    throw new AggregatorException("Cannot validate signature: missing certificate");
                }
                SignUtils.verifySignature(samlAssertion.getSignature(), info.getCertificates().get(0));

                if (!samlResponse.getInResponseTo().equals(requestId)) {
                    throw new AggregatorException("Request ID mismatch");
                }

                List<AttributeStatement> attrStat = samlAssertion.getAttributeStatements();
                if (attrStat == null || attrStat.size() == 0) {
                    throw new AggregatorException("Missing attribute statement");
                }

                List<Attribute> attrList = attrStat.get(0).getAttributes();
                if (attrList != null) {
                    for (Attribute attribute : attrList) {

                        List<XMLObject> xValues = attribute.getAttributeValues();
                        if (xValues != null) {

                            List<String> aValues = new ArrayList<String>(xValues.size());
                            for (XMLObject value : xValues) {
                                aValues.add(value.getDOM().getTextContent().trim());
                            }

                            result.put(attribute.getName(), aValues);
                        }
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

    private SOAPClient buildSOAPClient()
        throws AggregatorException {

        X509KeyManager keyManager = configuration.getKeyManager();
        X509TrustManager trustManager = configuration.getTrustManager();

        HttpClientBuilder httpClientBuilder = new HttpClientBuilder();
        httpClientBuilder.setContentCharSet("UTF-8");
        httpClientBuilder.setConnectionTimeout(configuration.getConnectionTimeout());
        httpClientBuilder.setMaxTotalConnections(configuration.getMaxRequests());
        httpClientBuilder.setMaxConnectionsPerHost(configuration.getMaxRequests());
        httpClientBuilder.setReceiveBufferSize(configuration.getBufferSize());
        httpClientBuilder.setSendBufferSize(configuration.getBufferSize());

        if (keyManager != null && trustManager != null) {
            TLSProtocolSocketFactory factory = new TLSProtocolSocketFactory(keyManager, trustManager);
            httpClientBuilder.setHttpsProtocolSocketFactory(factory);
        }

        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(httpClientBuilder.getMaxTotalConnections());
        return new HttpSOAPClient(httpClientBuilder.buildClient(), parserPool);

    }

}