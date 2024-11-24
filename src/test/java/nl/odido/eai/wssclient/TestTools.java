package nl.odido.eai.wssclient;

import javax.xml.xpath.XPath;
import java.io.FileNotFoundException;
import java.io.IOException;

public class TestTools {

    private final XmlTools.MyNamespaceContext myNamespaceCtx = new XmlTools.MyNamespaceContext();
    private final ClassLoader classloader = Thread.currentThread().getContextClassLoader();

    String readResourceFile(String fileName) throws IOException {
        var res = classloader.getResourceAsStream(fileName);
        if (res == null)
            throw new FileNotFoundException(fileName);
        return new String(res.readAllBytes());
    }

    XPath newXpath() {
        var factory = new net.sf.saxon.xpath.XPathFactoryImpl();
        var xpath = factory.newXPath();
        xpath.setNamespaceContext(myNamespaceCtx);
        return xpath;
    }

}
