package nl.odido.eai.wssclient;

import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.util.thread.ExecutorThreadPool;

public class ProxyServer {

    static Logger log = Logger.getLogger(ProxyServer.class.getName());
    final Server server;

    public ProxyServer(Handler handler, long idleTimeoutSeconds, String host, int port) {
        server = createServer(handler, idleTimeoutSeconds, host, port);
    }

    public void start() throws Exception {
        server.start();
        log.info("started HTTP server");
    }

    public void stop() throws Exception {
        server.stop();
        log.info("stopped HTTP server");
    }

    protected Server createServer(Handler handler, long idleTimeoutSeconds, String host, int port) {

        ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(
                4,
                8,
                idleTimeoutSeconds,
                TimeUnit.SECONDS,
                new SynchronousQueue<>());

        threadPoolExecutor.prestartAllCoreThreads();
        ExecutorThreadPool serverThreadPool = new ExecutorThreadPool(threadPoolExecutor);

        HttpConnectionFactory httpConnectionFactory = new HttpConnectionFactory();
        ConnectionFactory[] factories = {httpConnectionFactory};

        Server server = new Server(serverThreadPool);
        server.setHandler(handler);

        ServerConnector connector = new ServerConnector(server, factories);
        connector.setHost(host);
        connector.setPort(port);
        connector.setIdleTimeout(idleTimeoutSeconds * 1000);
        server.addConnector(connector);

        log.info("created HTTP server");
        return server;
    }
}
