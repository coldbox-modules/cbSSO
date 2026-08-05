package cbsso.opensaml;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import net.shibboleth.utilities.java.support.security.impl.RandomIdentifierGenerationStrategy;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;

public class OpenSAMLUtils {
    private static Logger logger = LoggerFactory.getLogger(OpenSAMLUtils.class);
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

    static {
        secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();

    }

    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object = null;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Could not create SAML object");
        }

        return object;
    }

    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static void logSAMLObject(final XMLObject object) {
        Element element = null;

        if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned()
                && object.getDOM() != null) {
            element = object.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
                out.marshall(object);
                element = object.getDOM();

            } catch (MarshallingException e) {
                logger.error(e.getMessage(), e);
            }
        }
        String xmlString = SerializeSupport.prettyPrintXML(element);

        logger.info(xmlString);

    }

    public static String stringifySAMLObject(final XMLObject object) {
        Element element = null;

        if (object instanceof SignableSAMLObject && ((SignableSAMLObject) object).isSigned()
                && object.getDOM() != null) {
            element = object.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
                out.marshall(object);
                element = object.getDOM();

            } catch (MarshallingException e) {
                logger.error(e.getMessage(), e);
            }
        }

        return SerializeSupport.prettyPrintXML(element);
    }

    public static DocumentBuilderFactory secureDocumentBuilderFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        return factory;
    }

    public static Response parseResponse(String samlResponse) throws Exception {
        DocumentBuilder builder = secureDocumentBuilderFactory().newDocumentBuilder();
        Document document = builder.parse(new ByteArrayInputStream(samlResponse.getBytes(StandardCharsets.UTF_8)));

        Element element = document.getDocumentElement();
        UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
        Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
        if (unmarshaller == null) {
            throw new Exception("Document is not a saml2p:Response: no unmarshaller for "
                    + element.getNamespaceURI() + ":" + element.getLocalName());
        }

        XMLObject xmlObject = unmarshaller.unmarshall(element);
        if (!(xmlObject instanceof Response)) {
            throw new Exception("Document is not a saml2p:Response: got " + xmlObject.getElementQName());
        }
        return (Response) xmlObject;
    }
}