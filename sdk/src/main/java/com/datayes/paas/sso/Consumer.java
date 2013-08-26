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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URLEncoder;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

public class Consumer {
    public static final String SAML_LOGOUT_RESPONSE = "saml2p:LogoutResponse";
    public static final String SAML_LOGOUT_REQUEST = "saml2p:LogoutRequest";
    private static final String USER = "user";
    private final String consumerUrl;
    private final boolean cookie;
    private String authUrl;
    private String AuthReqRandomId = Integer.toHexString(new Double(Math.random()).intValue());
    private Map<String, HttpSession> userSessions = new ConcurrentHashMap<String, HttpSession>();

    public Consumer(String authUrl, String consumerUrl, boolean cookie) {
        this.authUrl = authUrl;
        this.consumerUrl = consumerUrl;
        this.cookie = cookie;
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean process(HttpServletRequest request, HttpServletResponse response) throws IOException {
        boolean consumerRequest = consumerUrl.equals(request.getRequestURL().toString());
        User user = SsoContext.getUser();
        String method = request.getMethod();
        boolean post = "POST".equals(method);
        String samlResponse = request.getParameter("SAMLResponse");
        String samlRequest = request.getParameter("SAMLRequest");
        if (consumerRequest) {
            if (post) {
                if (samlRequest != null) { // single sign out request
                    doLogout(response, samlRequest);
                } else if (samlResponse != null) {
                    XMLObject samlResponseObj = unmarshall(samlResponse);
                    String samlResponseNodeName = samlResponseObj.getDOM().getNodeName();
                    if (SAML_LOGOUT_RESPONSE.equals(samlResponseNodeName)) { // logout response
                        doLogout(request, response);
                    } else { // login response
                        doLogin(request, response, samlResponseObj);
                    }
                } else {
                    invalidRequest(response);
                }
            } else if (request.getParameter("logout") != null) { // logout request
                sendLogoutRequest(response, user);
            } else {
                invalidRequest(response);
            }
            return true;
        } else {
            if (user == null) { // do auth
                doAuth(request, response);
                return true;
            } else {
                return false;
            }
        }
    }

    private void sendLogoutRequest(HttpServletResponse response, User user) throws IOException {
        LogoutRequest logoutRequest = buildLogoutRequest(user);
        response.sendRedirect(authUrl + "?SAMLRequest=" + marshall(logoutRequest) + "&RelayState=");
    }

    private void doAuth(HttpServletRequest request, HttpServletResponse response) throws IOException {
        AuthnRequest authRequest = buildAuthRequest();
        String relayState = request.getRequestURL().toString();
        String queryString = request.getQueryString();
        if (queryString != null) relayState += "?" + queryString;
        String url = authUrl + "?SAMLRequest=" + marshall(authRequest) + "&RelayState=" + URLEncoder.encode(relayState, "UTF-8");
        response.sendRedirect(url);
    }

    private void doLogin(HttpServletRequest request, HttpServletResponse response, XMLObject samlResponseObj) throws IOException {
        String relayState = request.getParameter("RelayState");
        Response resp = (Response) samlResponseObj;

        Assertion assertion = resp.getAssertions().get(0);
        Map<String, String> attributes = new HashMap<String, String>();
        String name = null;
        if (assertion != null) {
            name = assertion.getSubject().getNameID().getValue();
            List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();
            if (attributeStatementList != null) {
                // we have received attributes of user
                for (AttributeStatement statment : attributeStatementList) {
                    List<Attribute> attributesList = statment.getAttributes();
                    for (Attribute attrib : attributesList) {
                        Element value = attrib.getAttributeValues().get(0).getDOM();
                        String attribValue = value.getTextContent();
                        attributes.put(attrib.getName(), attribValue);
                    }
                }
            }
        }
        if (name == null) {
            throw new IOException("sso login, user is null");
        } else {
            setUserContext(request, response, name);
            response.sendRedirect(relayState);
        }
    }

    private void setUserContext(HttpServletRequest request, HttpServletResponse response, String name) {
        if (cookie) {
            Cookie c = new Cookie(USER, name);
            response.addCookie(c);
        } else {
            request.getSession().setAttribute(USER, name);
        }
        userSessions.put(name, request.getSession(false));
    }

    private void doLogout(HttpServletRequest request, HttpServletResponse response) throws IOException {
        HttpSession session = request.getSession(false);
        if (session != null)
            session.invalidate();
        response.sendRedirect(request.getContextPath());
    }

    private void doLogout(HttpServletResponse response, String samlRequest) throws IOException {
        XMLObject samlRequestObj = unmarshall(samlRequest);
        if (!SAML_LOGOUT_REQUEST.equals(samlRequestObj.getDOM().getNodeName()))
            throw new IOException("invalid do logout request");
        String name = ((LogoutRequestImpl) samlRequestObj).getNameID().getValue();
        removeUserContext(response, name);
    }

    private void removeUserContext(HttpServletResponse response, String name) {
        if (cookie) {
            Cookie c = new Cookie(USER, name);
            c.setMaxAge(0);
            c.setPath("/");
            response.addCookie(c);
        } else {
            userSessions.get(name).invalidate();
            userSessions.remove(name);
        }
    }

    private void invalidRequest(HttpServletResponse response) throws IOException {
        response.sendError(405, "invalid consumer request");
    }

    private AuthnRequest buildAuthRequest() {
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");
        issuer.setValue(consumerUrl);

        NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
        NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
        nameIdPolicy.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        nameIdPolicy.setSPNameQualifier("Isser");
        nameIdPolicy.setAllowCreate(Boolean.TRUE);

		/* AuthnContextClass */
        AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "AuthnContextClassRef", "saml");
        authnContextClassRef.setAuthnContextClassRef("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");

		/* AuthnContex */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
        RequestedAuthnContext requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
        requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
        requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);

        /* Creation of AuthRequestObject */
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol", "AuthnRequest", "samlp");
        authRequest.setForceAuthn(Boolean.FALSE);
        authRequest.setIsPassive(Boolean.FALSE);
        authRequest.setIssueInstant(new DateTime());
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

    private String marshall(RequestAbstractType request) throws IOException {
        try {
            Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(request);
            Element dom = marshaller.marshall(request);

            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOut = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOut = new DeflaterOutputStream(byteArrayOut, deflater);

            XMLHelper.writeNode(dom, deflaterOut);
            deflaterOut.close();

            String message = Base64.encodeBytes(byteArrayOut.toByteArray(), Base64.DONT_BREAK_LINES);
            return URLEncoder.encode(message, "UTF-8").trim();
        } catch (MarshallingException e) {
            throw new IOException("encode request failure", e);
        }
    }

    private LogoutRequest buildLogoutRequest(User user) {
        LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();
        logoutReq.setID(createID());

        DateTime issueInstant = new DateTime();
        logoutReq.setIssueInstant(issueInstant);
        logoutReq.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + 5 * 60 * 1000));

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(consumerUrl);
        logoutReq.setIssuer(issuer);

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:entity");
        nameId.setValue(user.getName());
        logoutReq.setNameID(nameId);

        SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();
        sessionIndex.setSessionIndex(UUID.randomUUID().toString());
        logoutReq.getSessionIndexes().add(sessionIndex);

        logoutReq.setReason("Single Logout");

        return logoutReq;
    }

    private String createID() {
        byte[] bytes = new byte[20];
        new Random().nextBytes(bytes);
        char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};
        char[] chars = new char[40];
        for (int i = 0; i < bytes.length; i++) {
            int left = (bytes[i] >> 4) & 0x0f;
            int right = bytes[i] & 0x0f;
            chars[i * 2] = charMapping[left];
            chars[i * 2 + 1] = charMapping[right];
        }
        return String.valueOf(chars);
    }

    private XMLObject unmarshall(String message) throws IOException {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();

            Inflater inflater = new Inflater(true);
            InflaterInputStream inflaterIn = new InflaterInputStream(new ByteArrayInputStream(Base64.decode(message)), inflater);

            Document document = docBuilder.parse(inflaterIn);
            inflaterIn.close();
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            return unmarshaller.unmarshall(element);
        } catch (Exception e) {
            throw new IOException("unmarshall message failure, message: \n" + message, e);
        }
    }
}
