package cbsso.opensaml;

import java.io.StringReader;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Support;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class AuthResponseValidator {

    private List<X509Certificate> certs = new ArrayList<X509Certificate>();

    public void cacheCerts(String federationMetaDataURL)
            throws Exception {

        certs = new ArrayList<X509Certificate>();

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(new URI(federationMetaDataURL))
                .GET()
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("Response Code: " + response.statusCode());

        // Parse the response body as XML
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        String body = response.body();

        if (body.startsWith("\uFEFF")) {
            body = body.substring(1);
        }

        Document doc = builder.parse(new InputSource(new StringReader(body)));

        NodeList elements = doc.getElementsByTagName("IDPSSODescriptor");

        for (int i = 0; i < elements.getLength(); i++) {
            NodeList certNodes = ((Element) elements.item(i)).getElementsByTagName("X509Certificate");

            for (int j = 0; j < certNodes.getLength(); j++) {
                certs.add(X509Support.decodeCertificate(certNodes.item(j).getFirstChild().getNodeValue()));
            }
        }

    }

    public Response parseAndValidate(
            String rawSAMLXML,
            String issuer) throws Exception {

        Response res = OpenSAMLUtils.parseResponse(rawSAMLXML);

        if (!validateIssuer(res, issuer)) {
            throw new Exception("Invalid issuer");
        }

        for (Assertion a : res.getAssertions()) {
            verifySignature(res);

            if (!validateConditions(res.getAssertions().get(0))) {
                throw new Exception("Invalid conditions");
            }
        }

        return res;
    }

    private void verifySignature(Response response) throws SignatureException {

        for (X509Certificate cert : certs) {
            try {
                BasicX509Credential credential = new BasicX509Credential(cert);
                SignatureValidator.validate(response.getAssertions().get(0).getSignature(), credential);
                return;
            } catch (Exception e) {

            }
        }

        throw new SignatureException();
    }

    private boolean validateConditions(Assertion assertion) {
        Conditions conditions = assertion.getConditions();
        Instant now = Instant.now();
        return conditions.getNotBefore().isBefore(now) && conditions.getNotOnOrAfter().isAfter(now);
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
