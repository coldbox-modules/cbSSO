package cbsso.opensaml;

import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class AuthResponseValidator {

    private static final Duration CLOCK_SKEW = Duration.ofSeconds(60);

    // Certificate loading is lazy, so this fetch happens on a user's first sign-in and an
    // unresponsive IdP would otherwise hold that request thread open indefinitely.
    private static final Duration METADATA_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration METADATA_REQUEST_TIMEOUT = Duration.ofSeconds(10);

    private List<X509Certificate> certs = new ArrayList<X509Certificate>();

    public void cacheCerts(String federationMetaDataURL) throws Exception {

        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(METADATA_CONNECT_TIMEOUT)
                .build();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(federationMetaDataURL))
                .timeout(METADATA_REQUEST_TIMEOUT)
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new Exception("Federation metadata request returned HTTP " + response.statusCode()
                    + " for " + federationMetaDataURL);
        }

        String body = response.body();

        if (body.startsWith("\uFEFF")) {
            body = body.substring(1);
        }

        cacheCertsFromMetadata(body);
    }

    public void cacheCertsFromMetadata(String metadataXML) throws Exception {

        List<X509Certificate> parsedCerts = new ArrayList<X509Certificate>();

        DocumentBuilder builder = OpenSAMLUtils.secureDocumentBuilderFactory().newDocumentBuilder();
        Document doc = builder.parse(new InputSource(new StringReader(metadataXML)));

        NodeList descriptors = doc.getElementsByTagNameNS("*", "IDPSSODescriptor");

        for (int i = 0; i < descriptors.getLength(); i++) {
            NodeList certNodes = ((Element) descriptors.item(i)).getElementsByTagNameNS("*", "X509Certificate");

            for (int j = 0; j < certNodes.getLength(); j++) {
                parsedCerts.add(X509Support.decodeCertificate(certNodes.item(j).getTextContent().trim()));
            }
        }

        if (parsedCerts.isEmpty()) {
            throw new Exception("No IDPSSODescriptor X509Certificate elements found in federation metadata");
        }

        certs = parsedCerts;
    }

    /**
     * @return the validated Assertion serialized as XML — the exact element whose signature verified.
     * @throws Exception on ANY validation failure.
     */
    public String parseAndValidateAssertion(String rawSAMLXML, String expectedIssuer, String expectedAudience,
            String expectedRecipient) throws Exception {

        // Named before anything is parsed. An unset audience or recipient would otherwise reject every
        // assertion with "no Audience matches this service provider """, which reads as the IdP's fault
        // rather than as this provider being misconfigured.
        requireConfigured("expectedIssuer", expectedIssuer);
        requireConfigured("expectedAudience", expectedAudience);
        requireConfigured("expectedRecipient", expectedRecipient);

        Response res = OpenSAMLUtils.parseResponse(rawSAMLXML);

        if (res.getStatus() == null
                || res.getStatus().getStatusCode() == null
                || !StatusCode.SUCCESS.equals(res.getStatus().getStatusCode().getValue())) {
            throw new Exception("Response status is not " + StatusCode.SUCCESS);
        }

        if (!validateIssuer(res, expectedIssuer)) {
            throw new Exception("Response issuer does not match expected issuer");
        }

        if (!res.getEncryptedAssertions().isEmpty()) {
            throw new Exception("Response contains EncryptedAssertion elements; this module cannot decrypt them");
        }

        if (res.getAssertions().size() != 1) {
            throw new Exception("Response must contain exactly one Assertion, found " + res.getAssertions().size());
        }

        Assertion assertion = res.getAssertions().get(0);

        Signature signature = assertion.getSignature();
        if (signature == null) {
            throw new Exception("Assertion is not signed; a signed Assertion is required");
        }

        // Primary XSW defence: the signature must conform to the SAML signature profile
        // (enveloped, single Reference resolving to the signature's own parent) before any
        // cryptographic verification happens.
        try {
            new SAMLSignatureProfileValidator().validate(signature);
        } catch (SignatureException e) {
            throw new SignatureException(
                    "Assertion signature does not conform to the SAML signature profile: " + e.getMessage(), e);
        }

        verifyReferenceBindsAssertion(signature, assertion);

        verifySignature(signature);

        validateAssertionIssuer(assertion, expectedIssuer);

        validateValidityWindow(assertion);

        validateAudience(assertion, expectedAudience);

        validateRecipient(assertion, expectedRecipient);

        validateAuthnStatement(assertion);

        Element dom = assertion.getDOM();
        if (dom == null) {
            throw new Exception("Validated assertion has no DOM element to serialize");
        }
        return SerializeSupport.nodeToString(dom);
    }

    // Checked after the signature, and on the Assertion rather than the Response: Core 2.3.3 makes the
    // Assertion's own Issuer mandatory and it sits inside the signed element, whereas the Response's is
    // optional, unsigned, and therefore only ever the sender's word. The Response-level check above stays
    // because it fails an obvious misconfiguration cheaply, but this is the one that is worth anything.
    private void validateAssertionIssuer(Assertion assertion, String expectedIssuer) throws Exception {

        Issuer issuer = assertion.getIssuer();

        if (issuer == null || !expectedIssuer.equals(issuer.getValue())) {
            throw new Exception("Assertion issuer \"" + (issuer == null ? "" : issuer.getValue())
                    + "\" does not match the expected issuer \"" + expectedIssuer + "\"");
        }
    }

    private void verifyReferenceBindsAssertion(Signature signature, Assertion assertion) throws Exception {

        String assertionId = assertion.getID();
        if (assertionId == null || assertionId.isEmpty()) {
            throw new Exception("Assertion has no ID attribute, so its signature cannot be bound to it");
        }

        Element signatureElement = signature.getDOM();
        if (signatureElement == null) {
            throw new Exception("Signature has no DOM element");
        }

        NodeList references = signatureElement.getElementsByTagNameNS(SignatureConstants.XMLSIG_NS, "Reference");
        if (references.getLength() != 1) {
            throw new Exception("Signature must contain exactly one Reference, found " + references.getLength());
        }

        String referenceURI = ((Element) references.item(0)).getAttribute("URI");
        String expectedURI = "#" + assertionId;
        if (!expectedURI.equals(referenceURI)) {
            throw new Exception("Signature Reference URI \"" + referenceURI
                    + "\" is not bound to the assertion being used (expected \"" + expectedURI + "\")");
        }
    }

    private void verifySignature(Signature signature) throws SignatureException {

        if (certs.isEmpty()) {
            throw new SignatureException(
                    "No IdP signing certificates are cached; cacheCerts() must succeed before validation");
        }

        for (X509Certificate cert : certs) {
            try {
                SignatureValidator.validate(signature, new BasicX509Credential(cert));
                return;
            } catch (SignatureException e) {
                // this cert did not verify; try the next cached cert
            }
        }

        throw new SignatureException("Assertion signature did not verify against any of the "
                + certs.size() + " cached IdP certificate(s)");
    }

    // SAML 2.0 Profiles 4.1.4.2 (Web Browser SSO) requires the bearer SubjectConfirmationData to
    // carry NotOnOrAfter, and this module has no replay protection (no InResponseTo check, no
    // assertion-ID cache), so an assertion with no expiry at all would be replayable indefinitely.
    // Therefore: at least one upper bound is mandatory — Conditions/@NotOnOrAfter or a bearer
    // SubjectConfirmationData/@NotOnOrAfter — and every bound that IS present is enforced, with a
    // 60s skew because IdP and app clocks differ.
    private void validateValidityWindow(Assertion assertion) throws Exception {

        Instant now = Instant.now();
        boolean hasUpperBound = false;

        Conditions conditions = assertion.getConditions();
        if (conditions != null) {
            Instant notBefore = conditions.getNotBefore();
            if (notBefore != null && now.plus(CLOCK_SKEW).isBefore(notBefore)) {
                throw new Exception("Assertion is not yet valid: Conditions NotBefore=" + notBefore);
            }

            Instant notOnOrAfter = conditions.getNotOnOrAfter();
            if (notOnOrAfter != null) {
                hasUpperBound = true;
                if (!now.minus(CLOCK_SKEW).isBefore(notOnOrAfter)) {
                    throw new Exception("Assertion has expired: Conditions NotOnOrAfter=" + notOnOrAfter);
                }
            }
        }

        if (assertion.getSubject() != null) {
            for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
                if (!SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())) {
                    continue;
                }

                SubjectConfirmationData data = confirmation.getSubjectConfirmationData();
                if (data == null) {
                    continue;
                }

                Instant notBefore = data.getNotBefore();
                if (notBefore != null && now.plus(CLOCK_SKEW).isBefore(notBefore)) {
                    throw new Exception(
                            "Assertion is not yet valid: bearer SubjectConfirmationData NotBefore=" + notBefore);
                }

                Instant notOnOrAfter = data.getNotOnOrAfter();
                if (notOnOrAfter != null) {
                    hasUpperBound = true;
                    if (!now.minus(CLOCK_SKEW).isBefore(notOnOrAfter)) {
                        throw new Exception("Assertion has expired: bearer SubjectConfirmationData NotOnOrAfter="
                                + notOnOrAfter);
                    }
                }
            }
        }

        if (!hasUpperBound) {
            throw new Exception("Assertion carries no expiry: neither Conditions NotOnOrAfter nor a bearer "
                    + "SubjectConfirmationData NotOnOrAfter is present");
        }
    }

    // Without this, an assertion the IdP minted for a different relying party verifies here and signs the
    // holder in. Profiles 4.1.4.2 requires an AudienceRestriction naming the SP, so - as with the expiry
    // above - absence is a rejection, not a pass.
    private void requireConfigured(String name, String value) throws Exception {

        if (value == null || value.trim().isEmpty()) {
            throw new Exception("Cannot validate an assertion: " + name + " is not configured on this provider");
        }
    }

    private void validateAudience(Assertion assertion, String expectedAudience) throws Exception {

        Conditions conditions = assertion.getConditions();
        List<AudienceRestriction> restrictions = conditions == null
                ? new ArrayList<AudienceRestriction>()
                : conditions.getAudienceRestrictions();

        if (restrictions.isEmpty()) {
            throw new Exception("Assertion carries no Conditions/AudienceRestriction, so it is not bound to "
                    + "this service provider \"" + expectedAudience + "\"");
        }

        for (AudienceRestriction restriction : restrictions) {
            for (Audience audience : restriction.getAudiences()) {
                if (expectedAudience.equals(audience.getURI())) {
                    return;
                }
            }
        }

        throw new Exception("No Audience in the assertion's AudienceRestriction matches this service provider \""
                + expectedAudience + "\"");
    }

    // The Recipient binds the assertion to this exact ACS endpoint, so one captured at another SP's endpoint
    // cannot be replayed here.
    //
    // Compared without case because the two sides derive the URL differently: an IdP echoes the Reply URL
    // exactly as it was registered, while cbsso builds the expected one through name.lcase() - so a
    // registration reading .../auth/MSSAML is checked against .../auth/mssaml. Both route to this same
    // handler on this same host, so they denote one endpoint and rejecting the pair fails every login
    // closed. This costs nothing: the host still has to be ours, so an assertion addressed to another
    // service provider is refused exactly as before.
    private void validateRecipient(Assertion assertion, String expectedRecipient) throws Exception {

        if (assertion.getSubject() != null) {
            for (SubjectConfirmation confirmation : assertion.getSubject().getSubjectConfirmations()) {
                if (!SubjectConfirmation.METHOD_BEARER.equals(confirmation.getMethod())) {
                    continue;
                }

                SubjectConfirmationData data = confirmation.getSubjectConfirmationData();
                if (data != null && expectedRecipient.equalsIgnoreCase(data.getRecipient())) {
                    return;
                }
            }
        }

        throw new Exception("No bearer SubjectConfirmationData has Recipient \"" + expectedRecipient + "\"");
    }

    private void validateAuthnStatement(Assertion assertion) throws Exception {

        if (assertion.getAuthnStatements().isEmpty()) {
            throw new Exception("Assertion contains no AuthnStatement, so it does not attest that the subject "
                    + "authenticated");
        }
    }

    private boolean validateIssuer(Response response, String expectedIssuer) {
        Issuer issuer = response.getIssuer();
        return issuer != null && expectedIssuer.equals(issuer.getValue());
    }

    public boolean validateAttributes(Assertion assertion, String expectedAttributeName,
            String expectedAttributeValue) {
        for (AttributeStatement attributeStatement : assertion.getAttributeStatements()) {
            for (Attribute attribute : attributeStatement.getAttributes()) {
                if (expectedAttributeName.equals(attribute.getName())
                        && attribute.getAttributeValues().stream()
                                .anyMatch(value -> expectedAttributeValue.equals(value.toString()))) {
                    return true;
                }
            }
        }
        return false;
    }

}
