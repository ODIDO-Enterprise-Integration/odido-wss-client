package nl.odido.eai.wssclient;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class XmlTools {

    private static final String docBuilderFactoryClass = "org.apache.xerces.jaxp.DocumentBuilderFactoryImpl";
    private static final String xpathFactoryClass = "net.sf.saxon.xpath.XPathFactoryImpl";
    private static final String xpathFactoryUri = XPathFactory.DEFAULT_OBJECT_MODEL_URI;
    private static final String transformerFactoryClass = "net.sf.saxon.TransformerFactoryImpl";

    private static final MyNamespaceContext myNamespaceCtx = new MyNamespaceContext();

    private static final ThreadLocal<DocumentBuilder> localDocumentBuilder = new ThreadLocal<>() {

        @Override
        public DocumentBuilder initialValue() {
            try {
                DocumentBuilderFactory domFactory = DocumentBuilderFactory.newInstance(docBuilderFactoryClass, ClassLoader.getSystemClassLoader());
                domFactory.setNamespaceAware(true);
                return domFactory.newDocumentBuilder();
            } catch (Exception e) {
                throw new RuntimeException("Could not create DocumentBuilder", e);
            }
        }

        @Override
        public DocumentBuilder get() {
            DocumentBuilder builder = super.get();
            builder.reset();
            return builder;
        }
    };

    private static final ThreadLocal<XPathFactory> localXPathFactory = ThreadLocal.withInitial(() -> {
        try {
            return XPathFactory.newInstance(xpathFactoryUri, xpathFactoryClass, ClassLoader.getSystemClassLoader());
        } catch (Exception e) {
            throw new RuntimeException("Could not create XPathFactory", e);
        }
    });

    private static final ThreadLocal<Transformer> localTransformer = ThreadLocal.withInitial(() -> {
        try {
            Transformer transformer = TransformerFactory.newInstance(transformerFactoryClass, ClassLoader.getSystemClassLoader()).newTransformer();
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            return transformer;
        } catch (Exception e) {
            throw new RuntimeException("Could not create Transformer", e);
        }
    });

    public static DocumentBuilder getDocumentBuilder() {
        return localDocumentBuilder.get();
    }

    public static XPathFactory getXPathFactory() {
        return localXPathFactory.get();
    }

    private static Transformer getTransformer() {
        return localTransformer.get();
    }

    public static XPath newXPath() {
        XPath x = getXPathFactory().newXPath();
        x.setNamespaceContext(myNamespaceCtx);
        return x;
    }

    public static String renderDOM(Document doc, boolean prettyPrint) throws TransformerException {
        return renderDOM((Node) doc, prettyPrint);
    }

    public static String renderDOM(Node doc, boolean prettyPrint) throws TransformerException {
        Transformer transformer = getTransformer();
        if (prettyPrint) {
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        } else {
            transformer.setOutputProperty(OutputKeys.INDENT, "no");
        }
        StringWriter sw = new StringWriter();
        transformer.transform(new DOMSource(doc), new StreamResult(sw));
        return sw.toString();
    }

    public static Document parseXML(String xml) throws SAXException, IOException {
        DocumentBuilder domBuilder = getDocumentBuilder();
        InputSource inputSource = new InputSource(new StringReader(xml));
        return domBuilder.parse(inputSource);
    }

    /**
     * Extended namespace context for XPATH queries
     *
     * @author Miklos Csuka
     */
    public static class MyNamespaceContext implements javax.xml.namespace.NamespaceContext {

        @Override
        public String getNamespaceURI(String prefix) {
            if (prefix == null) {
                throw new IllegalArgumentException("Null prefix");
            } else if ("xml".equals(prefix)) {
                return XMLConstants.XML_NS_URI;
            } else if ("xmlns".equals(prefix)) {
                return XMLConstants.XMLNS_ATTRIBUTE_NS_URI;
            } else if ("xs".equals(prefix) || "xsd".equals(prefix)) {
                return XMLConstants.W3C_XML_SCHEMA_NS_URI;
            } else if ("wsdl".equals(prefix)) {
                return "http://schemas.xmlsoap.org/wsdl/";
            } else if ("soap".equals(prefix)) {
                return "http://schemas.xmlsoap.org/wsdl/soap/";
            } else if ("soap-env".equalsIgnoreCase(prefix) || "soapenv".equals(prefix)) {
                return "http://schemas.xmlsoap.org/soap/envelope/";
            } else if ("wsse".equals(prefix)) {
                return "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
            } else if ("wsu".equals(prefix)) {
                return "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
            } else if ("ds".equals(prefix)) {
                return "http://www.w3.org/2000/09/xmldsig#";
            } else {
                return "";
            }
        }

        // This method isn't necessary for XPath processing.
        @Override
        public String getPrefix(String uri) {
            throw new UnsupportedOperationException();
        }

        // This method isn't necessary for XPath processing either.
        @Override
        public Iterator<String> getPrefixes(String uri) {
            throw new UnsupportedOperationException();
        }
    }

}

