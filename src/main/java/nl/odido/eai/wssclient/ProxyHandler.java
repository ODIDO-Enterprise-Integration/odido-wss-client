package nl.odido.eai.wssclient;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.wss4j.common.ext.WSSecurityException;
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ProxyHandler extends HandlerWrapper {

    static Logger log = Logger.getLogger(ProxyHandler.class.getName());

    private final HttpClient httpClient;
    private final String backendUrl;
    private final WssUtils wss;
    private final BigInteger certSerial;

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

        log.info("created HTTPS client");
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
        try {
            log.info("received request on path " + servletRequest.getRequestURI());
            HttpRequest clientRequest = copyRequest(servletRequest);
            log.info("forwarding request to " + clientRequest.getURI().toString() + " " + clientRequest.getBody().getLength());
            HttpContentResponse clientResponse = (HttpContentResponse) clientRequest.send();
            log.info("received response with status " + clientResponse.getStatus());
            setResponse(clientResponse, servletResponse);
            log.info("forwarding response");
        } catch (Exception e) {
            log.log(Level.WARNING, "error proxying request", e);
            setErrorResponse(500, e.toString(), servletResponse);
        }
        servletResponse.flushBuffer();
        request.setHandled(true);
    }

    static final HttpHeader[] SKIPPED_HEADERS = {
            HttpHeader.CONTENT_LENGTH,
            HttpHeader.HOST
    };

    static boolean copyHeader(String headerName) {
        for (HttpHeader h: SKIPPED_HEADERS) {
            if (h.is(headerName))
                return false;
        }
        return true;
    }

    private HttpRequest copyRequest(HttpServletRequest servletRequest) throws Exception {
        String path = servletRequest.getRequestURI();
        String url = backendUrl + path;
        HttpRequest clientRequest = (HttpRequest) httpClient.newRequest(url);
        clientRequest.method(servletRequest.getMethod());
        clientRequest.version(HttpVersion.HTTP_1_1);

        Enumeration<String> headers = servletRequest.getHeaderNames();
        while (headers.hasMoreElements()) {
            String h = headers.nextElement();
            if (copyHeader(h)) {
                String v = servletRequest.getHeader(h);
                clientRequest.addHeader(new HttpField(h, v));
            }
        }

        try (InputStream inputStream = servletRequest.getInputStream()) {
            if (inputStream != null) {
                int contentLength = servletRequest.getContentLength();
                int size = contentLength > 0 ? contentLength : 1024;
                try (ByteArrayOutputStream baos = new ByteArrayOutputStream(size)) {
                    byte[] buffer = new byte[1024];
                    int len = inputStream.read(buffer);
                    while (len >= 0) {
                        baos.write(buffer, 0, len);
                        len = inputStream.read(buffer);
                    }
                    String requestBody = baos.toString(StandardCharsets.UTF_8);
                    String newBody = wss.signWSS(requestBody);
                    var content = new StringRequestContent(newBody);
                    log.log(Level.INFO, "Signed request:\n" + newBody);
                    clientRequest.body(content);
                    clientRequest.addHeader(new HttpField(HttpHeader.CONTENT_LENGTH, "" + content.getLength()));
                }
            } else {
                clientRequest.body(new StringRequestContent(""));
            }
        }
        return clientRequest;
    }

    private void copyResponse(int status, HttpFields responseHeaders, String responseMessage, HttpServletResponse servletResponse) throws IOException {
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

    private void setResponse(HttpContentResponse clientResponse, HttpServletResponse servletResponse) throws Exception {
        int status = clientResponse.getStatus();
        String responseMessage = clientResponse.getContentAsString();
        var responseHeaders = clientResponse.getHeaders();
        log.info("Response message:\n" + responseMessage);
        if (status == 200 && responseMessage != null) {
            try {
                WSHandlerResult verifyResult = wss.verifyWSS(responseMessage);
                Set<BigInteger> serials = WssUtils.getSignerCertificateSerials(verifyResult);
                if (serials.contains(certSerial)) {
                    copyResponse(status, responseHeaders, responseMessage, servletResponse);
                } else {
                    setErrorResponse(400, "Signing certificate is not authorised", servletResponse);
                }
            } catch (WSSecurityException wsse) {
                log.log(Level.WARNING, "Signing certificate is not trusted", wsse);
                setErrorResponse(400, "Signing certificate is not trusted", servletResponse);
            }
        } else {
            copyResponse(status, responseHeaders, responseMessage, servletResponse);
        }
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

    protected void setErrorResponse(int status, String description, HttpServletResponse servletResponse) throws IOException {
        String faultstring = description
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;");

        String body = SOAP_FAULT.replace("%%FAULTSTRING%%", faultstring);
        log.info("Error response: " + status + "\n" + body);
        servletResponse.reset();
        servletResponse.setStatus(status);
        servletResponse.setContentType("text/xml; charset=utf-8");
        servletResponse.getOutputStream().print(body);
        servletResponse.setContentLength(servletResponse.getBufferSize());
    }

}
