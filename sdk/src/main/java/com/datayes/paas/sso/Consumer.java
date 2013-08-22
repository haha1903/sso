package com.datayes.paas.sso;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.util.*;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;

public class Consumer {

    private String authUrl;
    private String consumerUrl;
    private String AuthReqRandomId = Integer.toHexString(new Double(Math.random()).intValue());

    public Consumer(String authUrl, String consumerUrl) {
        this.authUrl = authUrl;
        this.consumerUrl = consumerUrl;
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public String buildRequestMessage(HttpServletRequest request) throws IOException {
        RequestAbstractType requestMessage = null;
        if (request.getParameter("logout") == null) {
            requestMessage = buildAuthnRequestObject();
        } else {
            requestMessage = buildLogoutRequest((String) request.getSession().getAttribute("user"));
        }
        String encodedRequestMessage = null;
        encodedRequestMessage = encodeRequestMessage(requestMessage);
        String relayState = request.getRequestURL().toString();
        String queryString = request.getQueryString();
        if (queryString != null)
            relayState += "?" + queryString;

        return authUrl + "?SAMLRequest=" + encodedRequestMessage + "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");
    }

    public static void main(String[] args) throws Exception {
        String s = "fZFBU8IwEIXv/opO7sU0FNpmaJkqMtMZhBlAD95CEmprmtRu6uC/txVR4cB1573d772dTA+Vcj5kA4XRMfIGGDlScyMKncfoaTt3QzRNbibAKkVqujC5ae1avrcSrJPNYqR4XQhevymx46+mLvO8FIpzVYlS5HlRl2IvKi53yMkAWplpsEzbGBHsDV0cuoRscUhxQEk48MfRC3KWxq70qkn3VjaXOo/86daSQc/cNpoaBgVQzSoJ1HK6SR8XlAwwVd+8tAXZIOf5lJL0KbvcGugx1/UldWOs4Uah5FgDXXaSbObMTVMxe93bTwrh7r+lVGpb2M+z29ftDDpy20GjBMDYrvTJ7X+G5PSYjYQ+W6aFPCS+l2ISkXQURA+zlPjpfeCNA39054+iMJoPf3ZcuH6nZ09OvgA=";
        Consumer consumer = new Consumer("a", "b");
        XMLObject unmarshall = consumer.unmarshall(s);
        System.out.println(unmarshall);
    }

    private LogoutRequest buildLogoutRequest(String user) {
        LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();
        logoutReq.setID(Util.createID());

        DateTime issueInstant = new DateTime();
        logoutReq.setIssueInstant(issueInstant);
        logoutReq.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + 5 * 60 * 1000));

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(consumerUrl);
        logoutReq.setIssuer(issuer);

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        nameId.setValue(user);
        logoutReq.setNameID(nameId);

        SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
        sessionIndex.setSessionIndex(UUID.randomUUID().toString());
        logoutReq.getSessionIndexes().add(sessionIndex);

        logoutReq.setReason("Single Logout");

        return logoutReq;
    }

    private AuthnRequest buildAuthnRequestObject() {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");
        issuer.setValue(consumerUrl);

        NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIdPolicy.setSPNameQualifier("Isser");
        nameIdPolicy.setAllowCreate(new Boolean(true));

		/* AuthnContextClass */
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef =
                authnContextClassRefBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion",
                        "AuthnContextClassRef",
                        "saml");
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		/* AuthnContex */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder =
                new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        DateTime issueInstant = new DateTime();

		/* Creation of AuthRequestObject */
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest =
                authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                        "AuthnRequest", "samlp");
        authRequest.setForceAuthn(new Boolean(false));
        authRequest.setIsPassive(new Boolean(false));
        authRequest.setIssueInstant(issueInstant);
        authRequest.setProtocolBinding("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
        authRequest.setAssertionConsumerServiceURL(consumerUrl);
        authRequest.setIssuer(issuer);
        authRequest.setNameIDPolicy(nameIdPolicy);
        authRequest.setRequestedAuthnContext(requestedAuthnContext);
        authRequest.setID(AuthReqRandomId);
        authRequest.setVersion(SAMLVersion.VERSION_20);

		/* Requesting Attributes. This Index value is registered in the IDP */
        /*String index = Util.getConfiguration(servletConfig, "AttributeConsumingServiceIndex");
        if (index != null && !index.equals("")) {
            authRequest.setAttributeConsumingServiceIndex(Integer.parseInt(index));
        }*/

        return authRequest;
    }

    private String encodeRequestMessage(RequestAbstractType requestMessage) throws IOException {
        try {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(requestMessage);
            Element authDOM = marshaller.marshall(requestMessage);

            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream =
                    new DeflaterOutputStream(byteArrayOutputStream,
                            deflater);

            StringWriter rspWrt = new StringWriter();
            XMLHelper.writeNode(authDOM, rspWrt);
            deflaterOutputStream.write(rspWrt.toString().getBytes());
            deflaterOutputStream.close();

		/* Encoding the compressed message */
            String encodedRequestMessage =
                    Base64.encodeBytes(byteArrayOutputStream.toByteArray(),
                            Base64.DONT_BREAK_LINES);
            return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }
    }

    public Map<String, String> processResponseMessage(String responseMessage) {
        try {
            XMLObject responseXmlObj = unmarshall(responseMessage);
            return getResult(responseXmlObj);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public Map<String, String> processRequestMessage(String samlRequest) {
        try {
            XMLObject requestXmlObj = unmarshall(samlRequest);

            if (requestXmlObj.getDOM().getNodeName().equals("saml2p:LogoutResponse")) {
                return null;
            }

            Response response = (Response) requestXmlObj;

            Assertion assertion = response.getAssertions().get(0);
            Map<String, String> resutls = new HashMap<String, String>();

		/*
         * If the request has failed, the IDP shouldn't send an assertion.
		 * SSO profile spec 4.1.4.2 <Response> Usage
		 */
            if (assertion != null) {

                String subject = assertion.getSubject().getNameID().getValue();
                resutls.put("Subject", subject); // get the subject

                List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

                if (attributeStatementList != null) {
                    // we have received attributes of user
                    Iterator<AttributeStatement> attribStatIter = attributeStatementList.iterator();
                    while (attribStatIter.hasNext()) {
                        AttributeStatement statment = attribStatIter.next();
                        List<Attribute> attributesList = statment.getAttributes();
                        Iterator<Attribute> attributesIter = attributesList.iterator();
                        while (attributesIter.hasNext()) {
                            Attribute attrib = attributesIter.next();
                            Element value = attrib.getAttributeValues().get(0).getDOM();
                            String attribValue = value.getTextContent();
                            resutls.put(attrib.getName(), attribValue);
                        }
                    }
                }
            }
            return resutls;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private XMLObject unmarshall(String responseMessage) throws Exception {

        org.apache.commons.codec.binary.Base64 base64Decoder =
                new org.apache.commons.codec.binary.Base64();

        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

        byte[] xmlBytes = base64Decoder.decode(responseMessage.getBytes("UTF-8"));

        Inflater inflater = new Inflater(true);
        inflater.setInput(xmlBytes);
        byte[] xmlMessageBytes = new byte[5000];
        int resultLength = inflater.inflate(xmlMessageBytes);

        if (inflater.getRemaining() > 0) {
            throw new RuntimeException("didn't allocate enough space to hold "
                    + "decompressed data");
        }

        inflater.end();
        //String decodedString = new String(xmlMessageBytes, 0, resultLength, "UTF-8");

        ByteArrayInputStream is = new ByteArrayInputStream(xmlMessageBytes, 0, resultLength);// (decodedString.getBytes("UTF-8"));  
        Document document = docBuilder.parse(is);//(decodedString);
        Element element = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        return unmarshaller.unmarshall(element);

    }

    /*
     * Process the response and returns the results
     */
    private Map<String, String> getResult(XMLObject responseXmlObj) {

        if (responseXmlObj.getDOM().getNodeName().equals("saml2p:LogoutResponse")) {
            return null;
        }

        Response response = (Response) responseXmlObj;

        Assertion assertion = response.getAssertions().get(0);
        Map<String, String> resutls = new HashMap<String, String>();

		/*
         * If the request has failed, the IDP shouldn't send an assertion.
		 * SSO profile spec 4.1.4.2 <Response> Usage
		 */
        if (assertion != null) {

            String subject = assertion.getSubject().getNameID().getValue();
            resutls.put("Subject", subject); // get the subject

            List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

            if (attributeStatementList != null) {
                // we have received attributes of user
                Iterator<AttributeStatement> attribStatIter = attributeStatementList.iterator();
                while (attribStatIter.hasNext()) {
                    AttributeStatement statment = attribStatIter.next();
                    List<Attribute> attributesList = statment.getAttributes();
                    Iterator<Attribute> attributesIter = attributesList.iterator();
                    while (attributesIter.hasNext()) {
                        Attribute attrib = attributesIter.next();
                        Element value = attrib.getAttributeValues().get(0).getDOM();
                        String attribValue = value.getTextContent();
                        resutls.put(attrib.getName(), attribValue);
                    }
                }
            }
        }
        return resutls;
    }

    public String getConsumerUrl() {
        return consumerUrl;
    }
}
