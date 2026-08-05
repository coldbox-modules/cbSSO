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

    private List<X509Certificate> certs = new ArrayList<X509Certificate>();

    public void cacheCerts(String federationMetaDataURL) throws Exception {

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(federationMetaDataURL))
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
    public String parseAndValidateAssertion(String rawSAMLXML, String expectedIssuer) throws Exception {

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
