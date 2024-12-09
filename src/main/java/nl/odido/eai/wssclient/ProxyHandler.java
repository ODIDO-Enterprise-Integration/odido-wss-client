package nl.odido.eai.wssclient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.HttpContentResponse;
import org.eclipse.jetty.client.HttpRequest;
import org.eclipse.jetty.client.http.HttpClientTransportOverHTTP;
import org.eclipse.jetty.client.util.StringRequestContent;
import org.eclipse.jetty.http.*;
import org.eclipse.jetty.io.ClientConnector;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.HandlerWrapper;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.util.thread.ExecutorThreadPool;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * A Jetty HTTP request handler that
 * - signs SOAP requests received from the client
 * - forwards the signed request to the configured HTTPS server
 * - validates the signature of the received response
 * - forwards the received response to the client
 * Not for production use, because:
 * - does not validate the server certificates
 * - error handling and recovery is best-effort
 * - no performance tuning possibilities
 */
public class ProxyHandler extends HandlerWrapper {

    static Logger log = Logger.getLogger(ProxyHandler.class.getName());

    private final HttpClient httpClient;
    private final String backendUrl;
    private final WssUtils wss;
    private final BigInteger certSerial;

    /**
     * Create a new proxy handler
     * @param idleTimeoutSeconds Number of seconds before the client breaks idle connections
     * @param backendUrl HTTPS url of the back-end (e.g. https://some.server or https://some.server:1234)
     * @param wss The WssUtils to use for signing and signature validation
     * @param certSerial Serial number of the back-end's trusted signer certificate (no validation done if null)
     */
    public ProxyHandler(long idleTimeoutSeconds, String backendUrl, WssUtils wss, BigInteger certSerial) {
        httpClient = createClient(idleTimeoutSeconds);
        this.backendUrl = backendUrl;
        this.wss = wss;
        this.certSerial = certSerial;
    }

    protected HttpClient createClient(long idleTimeoutSeconds) {

        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        sslContextFactory.setValidateCerts(false);
        sslContextFactory.setValidatePeerCerts(false);
        sslContextFactory.setEndpointIdentificationAlgorithm("HTTPS");

        ClientConnector clientConnector = new ClientConnector();
        clientConnector.setSslContextFactory(sslContextFactory);

        HttpClient client = getHttpClient(idleTimeoutSeconds, clientConnector);

        log.info("created HTTPS client");
        return client;
    }

    private static HttpClient getHttpClient(long idleTimeoutSeconds, ClientConnector clientConnector) {
        HttpClient client = new HttpClient(new HttpClientTransportOverHTTP(clientConnector));

        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(
                4,
                8,
                idleTimeoutSeconds,
                TimeUnit.SECONDS,
                new SynchronousQueue<>());

        threadPoolExecutor.prestartAllCoreThreads();
        ExecutorThreadPool clientThreadPool = new ExecutorThreadPool(threadPoolExecutor);

        client.setExecutor(clientThreadPool);
        client.setConnectTimeout(1000L);
        client.setIdleTimeout(idleTimeoutSeconds * 1000);
        return client;
    }

    public void startClient() throws Exception {
        httpClient.start();
    }

    public void stopClient() throws Exception {
        httpClient.stop();
    }

    @Override
    public void handle(String uri, final Request request, HttpServletRequest servletRequest,
                       HttpServletResponse servletResponse) throws IOException {
        int errorStatus = 400;
        try {
            log.info("received request on path " + servletRequest.getRequestURI());
            HttpRequest clientRequest = createClientRequest(servletRequest);
            errorStatus = 500;
            log.info("forwarding request to " + clientRequest.getURI().toString() + " " + clientRequest.getBody().getLength());
            HttpContentResponse clientResponse = (HttpContentResponse) clientRequest.send();
            log.info("received response with status " + clientResponse.getStatus());
            setResponse(clientResponse, servletResponse);
            log.info("forwarding response");
        } catch (Exception e) {
            log.log(Level.WARNING, "error proxying request", e);
            setErrorResponse(errorStatus, e.toString(), servletResponse);
        }
        servletResponse.flushBuffer();
        request.setHandled(true);
    }

    private static final SortedSet<String> skippedHeaders = skippedHeaders();

    private static SortedSet<String> skippedHeaders () {
        SortedSet<String> set = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        HttpHeader[] hdrs = {
                HttpHeader.CONTENT_LENGTH,
                HttpHeader.HOST
        };
        for (var h: hdrs) {
            set.add(h.lowerCaseName());
        }
        return set;
    }

    private HttpRequest createClientRequest(HttpServletRequest servletRequest) throws Exception {
        String path = servletRequest.getRequestURI();
        String url = backendUrl + path;
        HttpRequest clientRequest = (HttpRequest) httpClient.newRequest(url);
        clientRequest.method(servletRequest.getMethod());
        clientRequest.version(HttpVersion.HTTP_1_1);

        Enumeration<String> headers = servletRequest.getHeaderNames();
        while (headers.hasMoreElements()) {
            String h = headers.nextElement();
            if (!skippedHeaders.contains(h)) {
                String v = servletRequest.getHeader(h);
                clientRequest.addHeader(new HttpField(h, v));
            }
        }

        try (InputStream inputStream = servletRequest.getInputStream()) {
            if (inputStream != null) {
                byte[] inputBytes = inputStream.readAllBytes();
                String requestBody = new String(inputBytes, StandardCharsets.UTF_8);
                String newBody = wss.signWSS(requestBody);
                log.log(Level.INFO, "Signed request:\n" + newBody);
                var content = new StringRequestContent(newBody);
                clientRequest.body(content);
                clientRequest.addHeader(new HttpField(HttpHeader.CONTENT_LENGTH, "" + content.getLength()));
            } else {
                clientRequest.body(new StringRequestContent(""));
            }
        }
        return clientRequest;
    }

    private void setResponse(HttpContentResponse clientResponse, HttpServletResponse servletResponse) throws Exception {
        int status = clientResponse.getStatus();
        String responseMessage = clientResponse.getContentAsString();
        var responseHeaders = clientResponse.getHeaders();
        log.info("Response message:\n" + responseMessage);
        if (status == 200 && responseMessage != null && certSerial != null) {
            try {
                WSHandlerResult verifyResult = wss.verifyWSS(responseMessage);
                Set<BigInteger> serials = WssUtils.getSignerCertificateSerials(verifyResult);
                if (!serials.contains(certSerial)) {
                    setErrorResponse(502, "Signing certificate is not authorised", servletResponse);
                    return;
                }
            } catch (Exception wsse) {
                log.log(Level.WARNING, "Error validating response signature", wsse);
                setErrorResponse(502, "Error validating response signature", servletResponse);
                return;
            }
        }
        Enumeration<String> headerNames = responseHeaders.getFieldNames();
        while (headerNames.hasMoreElements()) {
            String h = headerNames.nextElement();
            String v = responseHeaders.get(h);
            servletResponse.addHeader(h, v);
        }
        if (responseMessage == null) {
            servletResponse.getOutputStream().print("");
        } else {
            servletResponse.getOutputStream().print(responseMessage);
            servletResponse.setContentLength(servletResponse.getBufferSize());
        }
        servletResponse.setStatus(status);
    }

    private final static String SOAP_FAULT = """
            <?xml version="1.0" encoding="UTF-8"?>
            <env:Envelope xmlns:env="http://schemas.xmlsoap.org/soap/envelope/">
              <env:Body>
                <env:Fault>
                  <faultcode>env:Server</faultcode>
                  <faultstring>%%FAULTSTRING%%</faultstring>
                  <faultactor>WSS Proxy</faultactor>
                </env:Fault>
              </env:Body>
            </env:Envelope>
            """;

    private void setErrorResponse(int status, String description, HttpServletResponse servletResponse) throws IOException {
        String faultstring = description
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");

        String body = SOAP_FAULT.replace("%%FAULTSTRING%%", faultstring);
        log.info("Error response: " + status + "\n" + body);
        servletResponse.reset();
        servletResponse.setContentType("text/xml; charset=utf-8");
        servletResponse.getOutputStream().print(body);
        servletResponse.setContentLength(servletResponse.getBufferSize());
        servletResponse.setStatus(status);
    }

}
