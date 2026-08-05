package cbsso.opensaml;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;

class AuthResponseValidatorTest {

    private static final String IDP_ISSUER = "https://idp.example.org/test";
    private static final String SP_AUDIENCE = "https://sp.example.com/entity-id";
    private static final String ACS_RECIPIENT = "https://sp.example.com/cbsso/auth/entra";

    private static KeyPair keyPair;
    private static X509Certificate certificate;
    private static Credential signingCredential;
    private static String metadataXML;

    private AuthResponseValidator validator;

    @BeforeAll
    static void setUpClass() throws Exception {
        AuthNRequestGenerator.initOpenSAML();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        keyPair = kpg.generateKeyPair();

        X500Name dn = new X500Name("CN=cbsso-test-idp");
        Instant now = Instant.now();
        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                dn,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(Duration.ofDays(1))),
                Date.from(now.plus(Duration.ofDays(365))),
                dn,
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded()));
        certificate = new JcaX509CertificateConverter().getCertificate(
                certBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate())));

        signingCredential = new BasicX509Credential(certificate, keyPair.getPrivate());

        metadataXML = prefixedMetadata(Base64.getEncoder().encodeToString(certificate.getEncoded()));
    }

    @BeforeEach
    void setUp() throws Exception {
        validator = new AuthResponseValidator();
        validator.cacheCertsFromMetadata(metadataXML);
    }

    @Test
    void rejectsResponseWithZeroAssertions() throws Exception {
        String xml = serialize(buildResponse(IDP_ISSUER, StatusCode.SUCCESS));

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("exactly one Assertion"), e.getMessage());
    }

    @Test
    void rejectsResponseWithTwoAssertions() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion first = buildAssertion();
        attachSignature(first);
        response.getAssertions().add(first);
        response.getAssertions().add(buildAssertion());
        String xml = signAndSerialize(response, first.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("exactly one Assertion"), e.getMessage());
    }

    @Test
    void rejectsAssertionWhoseSignatureReferencesAnotherElement() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        String originalId = assertion.getID();
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        // XSW simulation: retarget the assertion's ID so the signature Reference
        // ("#" + originalId) no longer identifies the assertion being consumed.
        String tampered = xml.replace("ID=\"" + originalId + "\"", "ID=\"_attacker-controlled\"");
        assertTrue(!tampered.equals(xml), "tampering must have changed the document");

        assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(tampered, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
    }

    @Test
    void acceptsValidSignedSingleAssertionResponseAndReturnsThatAssertion() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        String assertionId = assertion.getID();
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        String returned = validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT);

        Element root = parse(returned).getDocumentElement();
        assertEquals("Assertion", root.getLocalName());
        assertEquals("urn:oasis:names:tc:SAML:2.0:assertion", root.getNamespaceURI());
        assertEquals(assertionId, root.getAttribute("ID"));
    }

    @Test
    void rejectsUnsignedAssertion() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        response.getAssertions().add(buildAssertion());
        String xml = serialize(response);

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("not signed"), e.getMessage());
    }

    @Test
    void responseLevelSignatureDoesNotSubstituteForAssertionSignature() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        response.getAssertions().add(buildAssertion());
        Signature signature = buildSignature();
        response.setSignature(signature);
        String xml = signAndSerialize(response, signature);

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("not signed"), e.getMessage());
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, "https://someone-else.example.org",
                        SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("issuer"), e.getMessage());
    }

    @Test
    void rejectsAssertionWhoseIssuerDiffersFromTheResponseIssuer() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        // The Response Issuer still names the expected IdP, so the unsigned wrapper looks correct; only the
        // signed Assertion disagrees. Signed by the trusted key, so nothing but the issuer check can reject it.
        assertion.setIssuer(buildIssuer("https://someone-else.example.org"));
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("Assertion issuer"), e.getMessage());
    }

    @Test
    void rejectsAssertionWithNoIssuer() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        assertion.setIssuer(null);
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("Assertion issuer"), e.getMessage());
    }

    @Test
    void rejectsNonSuccessStatus() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.AUTHN_FAILED);
        Assertion assertion = buildAssertion();
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("status"), e.getMessage());
    }

    @Test
    void rejectsExpiredAssertion() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        Instant past = Instant.now().minus(Duration.ofMinutes(10));
        assertion.getConditions().setNotBefore(past.minus(Duration.ofMinutes(5)));
        assertion.getConditions().setNotOnOrAfter(past);
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("expired"), e.getMessage());
    }

    @Test
    void rejectsAssertionWithNoExpiryAnywhere() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        assertion.setConditions(null);
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("no expiry"), e.getMessage());
    }

    @Test
    void acceptsAssertionWithOnlyBearerSubjectConfirmationExpiry() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        // Conditions still carry the AudienceRestriction, but no NotOnOrAfter of their own, so the bearer
        // SubjectConfirmationData is the only source of the upper bound.
        assertion.setConditions(buildConditions(SP_AUDIENCE));
        assertion.setSubject(buildBearerSubject(Instant.now().plus(Duration.ofMinutes(5))));
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        String returned = validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT);
        assertEquals("Assertion", parse(returned).getDocumentElement().getLocalName());
    }

    @Test
    void rejectsExpiredBearerSubjectConfirmationEvenWithValidConditions() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        assertion.setSubject(buildBearerSubject(Instant.now().minus(Duration.ofMinutes(10))));
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("SubjectConfirmationData NotOnOrAfter"), e.getMessage());
    }

    @Test
    void rejectsAssertionWithNoAudienceRestriction() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        Conditions conditions = buildConditions(null);
        conditions.setNotOnOrAfter(Instant.now().plus(Duration.ofMinutes(5)));
        assertion.setConditions(conditions);
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("no Conditions/AudienceRestriction"), e.getMessage());
    }

    @Test
    void rejectsAssertionIssuedToAnotherServiceProvider() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        Conditions conditions = buildConditions("https://another-sp.example.net/entity-id");
        conditions.setNotOnOrAfter(Instant.now().plus(Duration.ofMinutes(5)));
        assertion.setConditions(conditions);
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("No Audience"), e.getMessage());
    }

    @Test
    void acceptsAssertionWhoseAudienceRestrictionNamesThisServiceProviderAmongOthers() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        Audience other = OpenSAMLUtils.buildSAMLObject(Audience.class);
        other.setURI("https://another-sp.example.net/entity-id");
        assertion.getConditions().getAudienceRestrictions().get(0).getAudiences().add(0, other);
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        String returned = validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT);
        assertEquals("Assertion", parse(returned).getDocumentElement().getLocalName());
    }

    @Test
    void rejectsAssertionWhoseRecipientIsAnotherAssertionConsumerService() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        assertion.setSubject(buildBearerSubject("https://another-sp.example.net/acs", null));
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("Recipient"), e.getMessage());
    }

    @Test
    void rejectsAssertionWithNoBearerRecipient() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        assertion.setSubject(buildBearerSubject(null, null));
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("Recipient"), e.getMessage());
    }

    @Test
    void rejectsAssertionWithNoAuthnStatement() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        assertion.getAuthnStatements().clear();
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("no AuthnStatement"), e.getMessage());
    }

    @Test
    void acceptsAssertionBoundToThisServiceProviderWithAnAuthnStatement() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        assertion.setSubject(buildBearerSubject(ACS_RECIPIENT, Instant.now().plus(Duration.ofMinutes(5))));
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        String returned = validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT);

        Element root = parse(returned).getDocumentElement();
        assertEquals("Assertion", root.getLocalName());
        assertEquals(SP_AUDIENCE, root.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "Audience").item(0).getTextContent());
        assertEquals(1, root.getElementsByTagNameNS(
                "urn:oasis:names:tc:SAML:2.0:assertion", "AuthnStatement").getLength());
    }

    @Test
    void rejectsExcessivelyNestedDocument() {
        // No DTD, so disallow-doctype-decl does not help here: this is the nesting-depth case from
        // OpenSAML's 13 May 2026 advisory, and the parser has to refuse it.
        StringBuilder nested = new StringBuilder(
                "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">");
        for (int i = 0; i < 200; i++) {
            nested.append("<a>");
        }
        for (int i = 0; i < 200; i++) {
            nested.append("</a>");
        }
        nested.append("</samlp:Response>");

        // Asserting on the parser's own complaint, not merely that it threw: without the depth limit this
        // document is rejected later for having no Status, so a bare assertThrows would pass either way.
        Exception e = assertThrows(Exception.class, () -> validator.parseAndValidateAssertion(
                nested.toString(), IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage() != null && e.getMessage().contains("maxElementDepth"), e.getMessage());
    }

    @Test
    void namesAnUnconfiguredAudienceRatherThanBlamingTheAssertion() throws Exception {
        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        attachSignature(assertion);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, assertion.getSignature());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, "   ", ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("expectedAudience is not configured"), e.getMessage());
    }

    @Test
    void rejectsSignatureFromAnUntrustedKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair rogueKeys = kpg.generateKeyPair();
        Credential rogueCredential = new BasicX509Credential(certificate, rogueKeys.getPrivate());

        Response response = buildResponse(IDP_ISSUER, StatusCode.SUCCESS);
        Assertion assertion = buildAssertion();
        Signature signature = buildSignature();
        signature.setSigningCredential(rogueCredential);
        assertion.setSignature(signature);
        response.getAssertions().add(assertion);
        String xml = signAndSerialize(response, signature);

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("did not verify"), e.getMessage());
    }

    @Test
    void parsesCertsFromNamespacePrefixedMetadata() throws Exception {
        AuthResponseValidator fresh = new AuthResponseValidator();
        fresh.cacheCertsFromMetadata(metadataXML);
    }

    @Test
    void parsesCertsFromUnprefixedMetadata() throws Exception {
        String unprefixed = "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\""
                + IDP_ISSUER + "\">"
                + "<IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                + "<KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
                + "<X509Data><X509Certificate>"
                + Base64.getEncoder().encodeToString(certificate.getEncoded())
                + "</X509Certificate></X509Data></KeyInfo></KeyDescriptor>"
                + "</IDPSSODescriptor></EntityDescriptor>";

        AuthResponseValidator fresh = new AuthResponseValidator();
        fresh.cacheCertsFromMetadata(unprefixed);
    }

    @Test
    void rejectsMetadataContainingDoctype() {
        String xxe = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>" + metadataXML;

        assertThrows(Exception.class, () -> {
            AuthResponseValidator fresh = new AuthResponseValidator();
            fresh.cacheCertsFromMetadata(xxe);
        });
    }

    @Test
    void rejectsDocumentThatIsNotAResponse() throws Exception {
        Assertion bare = buildAssertion();
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(bare).marshall(bare);
        String xml = SerializeSupport.nodeToString(bare.getDOM());

        Exception e = assertThrows(Exception.class,
                () -> validator.parseAndValidateAssertion(xml, IDP_ISSUER, SP_AUDIENCE, ACS_RECIPIENT));
        assertTrue(e.getMessage().contains("not a saml2p:Response"), e.getMessage());
    }

    private static String prefixedMetadata(String base64Cert) {
        return "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\""
                + IDP_ISSUER + "\">"
                + "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">"
                + "<md:KeyDescriptor use=\"signing\">"
                + "<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">"
                + "<ds:X509Data><ds:X509Certificate>" + base64Cert + "</ds:X509Certificate></ds:X509Data>"
                + "</ds:KeyInfo></md:KeyDescriptor>"
                + "</md:IDPSSODescriptor></md:EntityDescriptor>";
    }

    private static Response buildResponse(String issuerValue, String statusCodeValue) {
        Response response = OpenSAMLUtils.buildSAMLObject(Response.class);
        response.setID("_" + UUID.randomUUID());
        response.setIssueInstant(Instant.now());
        response.setIssuer(buildIssuer(issuerValue));

        Status status = OpenSAMLUtils.buildSAMLObject(Status.class);
        StatusCode statusCode = OpenSAMLUtils.buildSAMLObject(StatusCode.class);
        statusCode.setValue(statusCodeValue);
        status.setStatusCode(statusCode);
        response.setStatus(status);

        return response;
    }

    // A fully valid assertion for the expected issuer, audience and recipient. The bearer
    // SubjectConfirmationData deliberately carries no NotOnOrAfter so that the expiry tests can control
    // where the upper bound comes from.
    private static Assertion buildAssertion() {
        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);
        assertion.setID("_" + UUID.randomUUID());
        assertion.setIssueInstant(Instant.now());
        assertion.setIssuer(buildIssuer(IDP_ISSUER));

        Conditions conditions = buildConditions(SP_AUDIENCE);
        conditions.setNotBefore(Instant.now().minus(Duration.ofMinutes(5)));
        conditions.setNotOnOrAfter(Instant.now().plus(Duration.ofMinutes(5)));
        assertion.setConditions(conditions);

        assertion.setSubject(buildBearerSubject(ACS_RECIPIENT, null));
        assertion.getAuthnStatements().add(buildAuthnStatement());

        return assertion;
    }

    private static Conditions buildConditions(String audienceValue) {
        Conditions conditions = OpenSAMLUtils.buildSAMLObject(Conditions.class);

        if (audienceValue != null) {
            AudienceRestriction restriction = OpenSAMLUtils.buildSAMLObject(AudienceRestriction.class);
            Audience audience = OpenSAMLUtils.buildSAMLObject(Audience.class);
            audience.setURI(audienceValue);
            restriction.getAudiences().add(audience);
            conditions.getAudienceRestrictions().add(restriction);
        }

        return conditions;
    }

    private static AuthnStatement buildAuthnStatement() {
        AuthnStatement statement = OpenSAMLUtils.buildSAMLObject(AuthnStatement.class);
        statement.setAuthnInstant(Instant.now().minus(Duration.ofSeconds(30)));

        AuthnContext context = OpenSAMLUtils.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef classRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        classRef.setURI(AuthnContext.PASSWORD_AUTHN_CTX);
        context.setAuthnContextClassRef(classRef);
        statement.setAuthnContext(context);

        return statement;
    }

    private static Subject buildBearerSubject(Instant notOnOrAfter) {
        return buildBearerSubject(ACS_RECIPIENT, notOnOrAfter);
    }

    private static Subject buildBearerSubject(String recipient, Instant notOnOrAfter) {
        Subject subject = OpenSAMLUtils.buildSAMLObject(Subject.class);
        SubjectConfirmation confirmation = OpenSAMLUtils.buildSAMLObject(SubjectConfirmation.class);
        confirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
        SubjectConfirmationData data = OpenSAMLUtils.buildSAMLObject(SubjectConfirmationData.class);
        data.setRecipient(recipient);
        data.setNotOnOrAfter(notOnOrAfter);
        confirmation.setSubjectConfirmationData(data);
        subject.getSubjectConfirmations().add(confirmation);
        return subject;
    }

    private static Issuer buildIssuer(String value) {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(value);
        return issuer;
    }

    private static Signature buildSignature() {
        Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        return signature;
    }

    private static void attachSignature(Assertion assertion) {
        assertion.setSignature(buildSignature());
    }

    private static String signAndSerialize(Response response, Signature signature) throws Exception {
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        Signer.signObject(signature);
        return SerializeSupport.nodeToString(response.getDOM());
    }

    private static String serialize(Response response) throws Exception {
        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        return SerializeSupport.nodeToString(response.getDOM());
    }

    private static Document parse(String xml) throws Exception {
        return OpenSAMLUtils.secureDocumentBuilderFactory().newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }
}
