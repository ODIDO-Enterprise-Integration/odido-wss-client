package nl.odido.eai.wssclient;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import jakarta.annotation.Nonnull;

import javax.security.auth.x500.X500Principal;
import javax.xml.transform.TransformerException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.WSSecTimestamp;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public class WssUtils {

    /**
     * Some of the most common non-standard OIDs used in certificate subjects
     */
    final static Map<String, String> customOidMap = Map.of(
            "1.2.840.113549.1.9.1", "emailAddress",
            "2.5.4.5", "serialNumber",
            "2.5.4.9", "streetAddress",
            "2.5.4.15", "businessCategory"
    );

    private final String signAlias;
    private final String signPassword;
    private final Crypto signer;
    private final Crypto verifier;
    private final List<BSPRule> ignoredBSPRules;
    private final WSSecurityEngine securityEngine;
    private static boolean engineInitd = false;

    private static final Logger logger = Logger.getLogger(WssUtils.class.getName());

    private WssUtils(String signAlias, String signPassword, Crypto signer, Crypto verifier, List<BSPRule> ignoredBSPRules, WSSecurityEngine securityEngine) {
        this.signAlias = signAlias;
        this.signPassword = signPassword;
        this.signer = signer;
        this.verifier = verifier;
        this.ignoredBSPRules = ignoredBSPRules;
        this.securityEngine = securityEngine;
    }

    /**
     * Create a new WssUtils instance, to sign SOAP messages and verify signatures
     * @param keystoreFile The keystore file, where the signing key-certificate pair is
     * @param keystorePassword Password of the keystore file. Key password must be the same
     * @param keystoreAlias Alias of the signing key
     * @param truststoreFile The truststore file, where the trusted certificates are
     * @param truststorePassword Password of the truststore file
     * @param ignoredBSPRuleNames List of BSP rules that can be ignored at the signature validation
     * @return A new WssUtils instance
     * @throws WSSecurityException
     */
    public static WssUtils newWssUtils(@Nonnull String keystoreFile,
                         @Nonnull String keystorePassword,
                         @Nonnull String keystoreAlias,
                         @Nonnull String truststoreFile,
                         @Nonnull String truststorePassword,
                         @Nonnull List<String> ignoredBSPRuleNames) throws WSSecurityException {

        WssUtils wss = new WssUtils(
                keystoreAlias,
                keystorePassword,
                createCryptoSigner(keystoreFile, keystorePassword, keystoreAlias),
                createCryptoVerifier(truststoreFile, truststorePassword),
                createIgnoredBSPRulesList(ignoredBSPRuleNames),
                new WSSecurityEngine());

        if (!engineInitd) {
            WSSConfig.init();
            engineInitd = true;
        }

        return wss;
    }

    private static List<BSPRule> createIgnoredBSPRulesList(@Nonnull List<String> ignoredBSPRuleNames) {
         return ignoredBSPRuleNames
                .stream()
                .map(ruleName -> {
                    try {
                        return BSPRule.valueOf(ruleName);
                    } catch (IllegalArgumentException iae) {
                        logger.log(Level.WARNING, "Invalid rule name defined in application properties: " + ruleName);
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();
    }

    private static Crypto createCryptoSigner(String keystoreFile, String keystorePassword, String keystoreAlias) throws WSSecurityException {
        Properties props = new Properties();
        props.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        props.setProperty("org.apache.wss4j.crypto.merlin.keystore.type", "jks");
        props.setProperty("org.apache.wss4j.crypto.merlin.keystore.alias", keystoreAlias);
        props.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", keystoreFile);
        props.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", keystorePassword);

        return CryptoFactory.getInstance(props);
    }

    private static Crypto createCryptoVerifier(String truststoreFile, String truststorePassword) throws WSSecurityException {
        Properties props = new Properties();
        props.setProperty("org.apache.wss4j.crypto.provider", "org.apache.wss4j.common.crypto.Merlin");
        props.setProperty("org.apache.wss4j.crypto.merlin.keystore.type", "jks");
        props.setProperty("org.apache.wss4j.crypto.merlin.keystore.file", truststoreFile);
        props.setProperty("org.apache.wss4j.crypto.merlin.keystore.password", truststorePassword);

        return CryptoFactory.getInstance(props);
    }

    /**
     * Verify signature of a SOAP message
     * @param message Signed SOAP message
     * @return Verification result
     * @throws SAXException
     * @throws IOException
     * @throws WSSecurityException
     * @throws XPathExpressionException
     * @throws IllegalArgumentException
     */
    public WSHandlerResult verifyWSS(String message) throws SAXException, IOException, WSSecurityException, XPathExpressionException, IllegalArgumentException {
        Document doc = XmlTools.parseXML(message);
        XPath xpath = XmlTools.newXPath();
        boolean fault = (xpath.evaluate("/SOAP-ENV:Envelope/SOAP-ENV:Body/SOAP-ENV:Fault", doc, XPathConstants.NODE) != null);
        if (!fault) {
            synchronized (verifier) {
                RequestData data = new RequestData();
                data.setActor("");
                data.setWssConfig(securityEngine.getWssConfig());
                data.setDecCrypto(verifier);
                data.setSigVerCrypto(verifier);
                data.setCallbackHandler(null);
                data.setIgnoredBSPRules(ignoredBSPRules);
                WSHandlerResult result = securityEngine.processSecurityHeader(doc, data);    // throws exception if fails
                if (result == null) {
                    throw new IllegalArgumentException("Message is not signed!");
                }
                return result;
            }
        }
        return null;
    }

    public static Set<String> getSignerCertificateSubjects(WSHandlerResult wssResult) {
        return getSignerCertificateSubjects(wssResult, customOidMap);
    }

    public static Set<String> getSignerCertificateSubjects(WSHandlerResult wssResult, Map<String, String> oidMap) {
        if (wssResult == null) {
            return Set.of();
        } else {
            return wssResult.getResults().stream()
                    .map(result -> (X509Certificate) result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE))
                    .filter(Objects::nonNull)
                    .map(cert -> cert.getSubjectX500Principal().getName(X500Principal.RFC2253, oidMap))
                    .collect(Collectors.toSet());
        }
    }

    public static Set<BigInteger> getSignerCertificateSerials(WSHandlerResult wssResult) {
        if (wssResult == null) {
            return Set.of();
        } else {
            return wssResult.getResults().stream()
                    .map(result -> (X509Certificate) result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE))
                    .filter(Objects::nonNull)
                    .map(X509Certificate::getSerialNumber)
                    .collect(Collectors.toSet());
        }
    }

    /**
     * Sign a SOAP message
     * @param message SOAP message as string
     * @return Signed SOAP message as string
     * @throws IOException
     * @throws SAXException
     * @throws WSSecurityException
     * @throws TransformerException
     */
    public String signWSS(String message) throws IOException, SAXException, WSSecurityException, TransformerException {

        Document doc = XmlTools.parseXML(message);

        WSSecHeader secHeader = createSecurityHeader(doc);
        WSSecSignature builder = createSignatureBuilder(secHeader, signAlias);

        Document signedDoc;
        synchronized (signer) {
            signedDoc = builder.build(signer);
        }

        return XmlTools.renderDOM(signedDoc, false);
    }

    private WSSecHeader createSecurityHeader(Document doc) throws WSSecurityException {
        WSSecHeader header = new WSSecHeader(doc);
        header.insertSecurityHeader();

        WSSecTimestamp timestamp = new WSSecTimestamp(header);
        timestamp.build();

        return header;
    }

    private WSSecSignature createSignatureBuilder(WSSecHeader secHeader, String keyAlias) {
        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo(keyAlias, signPassword);
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.prependBSTElementToHeader();

        builder.getParts().add(new WSEncryptionPart(WSConstants.TIMESTAMP_TOKEN_LN, WSConstants.WSU_NS, ""));
        builder.getParts().add(new WSEncryptionPart(WSConstants.ELEM_BODY, WSConstants.URI_SOAP11_ENV, ""));

        return builder;
    }
}
