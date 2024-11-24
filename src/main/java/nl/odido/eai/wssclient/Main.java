package nl.odido.eai.wssclient;

import org.apache.wss4j.dom.handler.WSHandlerResult;

import java.io.*;
import java.math.BigInteger;
import java.util.Collections;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

public class Main extends Thread {

    static Logger log = Logger.getLogger(Main.class.getName());

    // Configuration parameters. Please replace these with the configuration choice of yours (props file, env vars, KV storage, ...)

    // The provided keystore file contains a test key-certificate pair. If you want to use the proxy functionality,
    // use a keystore with a private/public key pair, where the certificate is whitelisted on Odido side
//    static final String keystoreFile = "./src/test/resources/wss_keystore.jks";
//    static final String keystorePassword = "secret";
//    static final String keystoreAlias = "wsscert";
    static final String keystoreFile = "C:/Projects/tls/client1_keystore.jks";
    static final String keystorePassword = "tibco123";
    static final String keystoreAlias = "client1-wss";

    // the provided truststore file contains Odido's test WSS certificate and the test WSS certificate from the keystore
    static final String truststoreFile = "./src/test/resources/wss_truststore.jks";
    static final String truststorePassword = "secret";

    static final int idleTimeoutSeconds = 60;
    static final BigInteger certSerial = new BigInteger("7cb95a8f8f9ca851b7869fb523dd51ca9a92cd7b", 16);
    static final String host = "0.0.0.0";
    static final int port = 8080;

    private static ProxyServer proxyServer = null;
    private static ProxyHandler proxyHandler = null;

    static String readFile(String fileName) throws IOException {
        try (FileReader fr = new FileReader(fileName); BufferedReader br = new BufferedReader(fr)) {
            return br.lines().collect(Collectors.joining("\n"));
        }
    }

    static void writeFile(String fileName, String contents) throws IOException {
        try (FileWriter fw = new FileWriter(fileName)) {
            fw.write(contents);
        }
    }

    public static void main(String[] args) {
        try {
            WssUtils wss = WssUtils.newWssUtils(keystoreFile, keystorePassword, keystoreAlias, truststoreFile, truststorePassword, Collections.emptyList());
            if (args.length == 3 && "sign".equals(args[0])) {
                String input = readFile(args[1]);
                log.fine("Read file " + args[1] + "\n" + input);
                String output = wss.signWSS(input);
                log.fine("Writing file " + args[2] + "\n" + output);
                writeFile(args[2], output);
            } else if (args.length == 2 && "verify".equals(args[0])) {
                String input = readFile(args[1]);
                log.fine("Read file " + args[1] + "\n" + input);
                WSHandlerResult result = wss.verifyWSS(input);
                if (result != null) {
                    Set<String> certSubjects = WssUtils.getSignerCertificateSubjects(result);
                    Set<BigInteger> certSerials = WssUtils.getSignerCertificateSerials(result);
                    log.info("Message is signed by certificates with subject " + certSubjects);
                    log.info("Message is signed by certificates with serial numbers " + certSerials);
                }

            } else if (args.length == 2 && "proxy".equals(args[0])) {
                Main mainLoop = new  Main();
                mainLoop.addShutdownHook();
                proxyHandler = new ProxyHandler(idleTimeoutSeconds, args[1], wss, certSerial);
                proxyServer = new ProxyServer(proxyHandler, idleTimeoutSeconds, host, port);
                proxyHandler.startClient();
                proxyServer.start();

                mainLoop.start();
            } else {
                System.out.println("""
                Usage:
                ------
                Sign a SOAP Message:
                   java -jar target/odido-wss-client-0.0.1-jar-with-dependencies.jar sign {input file to be signed} {signed output file}
                Validate a SOAP Message Signature:
                   java -jar target/odido-wss-client-0.0.1-jar-with-dependencies.jar verify {signed input file}
                Validate a SOAP Message Signature:
                   java -jar target/odido-wss-client-0.0.1-jar-with-dependencies.jar proxy {server url}
                """);
            }

        } catch (Throwable t) {
            log.log(Level.SEVERE, "Unexpected error", t);
        }
    }

    private void addShutdownHook() {
        Runtime.getRuntime().addShutdownHook(new Thread("shutdown-hook") {

            @Override
            public void run() {
                try {
                    if (proxyServer != null)
                        proxyServer.stop();
                    if (proxyHandler != null)
                        proxyHandler.stopClient();
                } catch (Exception e) {
                    log.log(Level.SEVERE, e, () -> "Unexcepted exception at shutdown");
                }
            }
        });
    }

    @Override
    public void run() {
        try {
            while (true) {
                sleep(10000);
            }
        } catch (InterruptedException ie) {
            log.log(Level.WARNING, ie, () -> "The thread was interrupted");
        }
    }


}

