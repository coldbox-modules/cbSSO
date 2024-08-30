package cbsso.opensaml;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;

import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.ParserPool;

public class AuthNRequestGenerator {

    private static boolean initialized = false;

    public static String generateAuthNRequest(String issuerId, String requestId)
            throws InitializationException, ComponentInitializationException {
        // initOpenSAML();
        AuthnRequest authnRequest = buildAuthnRequest(issuerId, requestId);
        return OpenSAMLUtils.stringifySAMLObject(authnRequest);
    }

    public synchronized static void initOpenSAML() throws InitializationException, ComponentInitializationException {
        if (initialized) {
            return;
        }
        XMLObjectProviderRegistry registry = new XMLObjectProviderRegistry();
        ConfigurationService.register(XMLObjectProviderRegistry.class, registry);

        registry.setParserPool(getParserPool());
        InitializationService.initialize();

        initialized = true;
    }

    private static ParserPool getParserPool() throws ComponentInitializationException {
        BasicParserPool parserPool = new BasicParserPool();
        parserPool.setMaxPoolSize(100);
        parserPool.setCoalescing(true);
        parserPool.setIgnoreComments(true);
        parserPool.setIgnoreElementContentWhitespace(true);
        parserPool.setNamespaceAware(true);
        parserPool.setExpandEntityReferences(false);
        parserPool.setXincludeAware(false);

        final Map<String, Boolean> features = new HashMap<String, Boolean>();
        features.put("http://xml.org/sax/features/external-general-entities", Boolean.FALSE);
        features.put("http://xml.org/sax/features/external-parameter-entities", Boolean.FALSE);
        features.put("http://apache.org/xml/features/disallow-doctype-decl", Boolean.TRUE);
        features.put("http://apache.org/xml/features/validation/schema/normalized-value", Boolean.FALSE);
        features.put("http://javax.xml.XMLConstants/feature/secure-processing", Boolean.TRUE);

        parserPool.setBuilderFeatures(features);

        parserPool.setBuilderAttributes(new HashMap<String, Object>());

        parserPool.initialize();

        return parserPool;
    }

    private static AuthnRequest buildAuthnRequest(String issuerId, String requestId) {
        AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class);
        authnRequest.setIssueInstant(Instant.now());
        // authnRequest.setDestination(IPD_SSO_DESTINATION);
        // authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
        // authnRequest.setAssertionConsumerServiceURL(SP_ASSERTION_CONSUMER_SERVICE_URL);
        authnRequest.setID(requestId);
        authnRequest.setIssuer(buildIssuer(issuerId));
        authnRequest.setNameIDPolicy(buildNameIdPolicy());

        return authnRequest;
    }

    private static NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
        nameIDPolicy.setAllowCreate(true);
        nameIDPolicy.setFormat(NameIDType.TRANSIENT);

        return nameIDPolicy;
    }

    private static Issuer buildIssuer(String issuerId) {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(issuerId);

        return issuer;
    }
}
