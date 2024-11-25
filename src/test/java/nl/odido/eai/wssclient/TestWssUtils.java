package nl.odido.eai.wssclient;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Set;

public class TestWssUtils {

    static WssUtils wss;
    private final TestTools tools = new TestTools();

    @BeforeAll
    public static void setup() throws Exception {

       wss = WssUtils.newWssUtils(
          "./src/test/resources/wss_keystore.jks",
          "secret",
          "wsscert",
          "./src/test/resources/wss_truststore.jks",
          "secret",
          Collections.emptyList()
          );
    }

    @Test
    public void testSignWSS() throws Exception {
        var inputXml = tools.readResourceFile("SoapInputMessage.xml");

        var signed = wss.signWSS(inputXml);

        var signedDoc = XmlTools.parseXML(signed);
        var xpath = tools.newXpath();

        Assertions.assertTrue(xpath.evaluateExpression("count(//soapenv:Header/wsse:Security/wsse:BinarySecurityToken) = 1", signedDoc, Boolean.class));
        Assertions.assertTrue(xpath.evaluateExpression("count(//ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference) = 1", signedDoc, Boolean.class));
        var idToken = xpath.evaluateExpression("//soapenv:Header/wsse:Security/wsse:BinarySecurityToken/@wsu:Id", signedDoc, String.class);
        var idRef = xpath.evaluateExpression("//soapenv:Header/wsse:Security/ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference/@URI", signedDoc, String.class);
        Assertions.assertEquals("#" + idToken, idRef);
    }

    @Test
    public void testValidateWSS() throws Exception {
        var inputXml = tools.readResourceFile("SoapInputMessage.xml");
        var signed = wss.signWSS(inputXml);

        var wssResult = wss.verifyWSS(signed);
        var subjects = WssUtils.getSignerCertificateSubjects(wssResult);
        var serials = WssUtils.getSignerCertificateSerials(wssResult);

        Assertions.assertEquals(subjects, Set.of("CN=testclient.acme.nl,OU=IT,O=ACME,L=Urk,ST=Flevoland,C=NL"));
        Assertions.assertEquals(serials, Set.of(new BigInteger("734eaf87f23dae80", 16)));
    }

}
