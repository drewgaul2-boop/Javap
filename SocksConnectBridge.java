package com.example.selectivetunnel;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Minimal loopback HTTP {@code CONNECT} proxy that dials upstream through a SOCKS5 proxy.
 *
 * <p>Why it exists: {@code java.net.http.HttpClient} cannot use SOCKS proxies. It can, however, use an
 * HTTP proxy, and a CONNECT tunnel keeps TLS end-to-end between the client and the target, so the
 * bridge only ever sees opaque bytes. Host names are passed to the SOCKS server unresolved, so DNS
 * for the target is resolved remotely (no local DNS leak).
 *
 * <p>Hardening: binds to the loopback interface only, accepts only {@code CONNECT}, and only for hosts
 * inside the configured target domain.
 */
final class SocksConnectBridge implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SocksConnectBridge.class);

    private static final int MAX_HEAD_BYTES = 16 * 1024;
    private static final int HEAD_READ_TIMEOUT_MS = 15_000;
    private static final int UPSTREAM_CONNECT_TIMEOUT_MS = 10_000;

    private final TunnelConfig config;
    private final ServerSocket server;
    private final ExecutorService pool;
    private volatile boolean closed;

    SocksConnectBridge(TunnelConfig config) throws IOException {
        this.config = config;
        this.server = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        AtomicInteger n = new AtomicInteger();
        ThreadFactory tf = r -> {
            Thread t = new Thread(r, "socks-bridge-" + n.incrementAndGet());
            t.setDaemon(true);
            return t;
        };
        this.pool = Executors.newCachedThreadPool(tf);
        if (config.hasCredentials()) {
            SocksCredentials.install(config);
        }
        pool.execute(this::acceptLoop);
        log.info("SOCKS5 bridge listening on {} -> socks5://{}:{}",
                server.getLocalSocketAddress(), config.proxyHost(), config.proxyPort());
    }

    /** HTTP proxy descriptor that {@code HttpClient} should use to reach this bridge. */
    Proxy asHttpProxy() {
        return new Proxy(Proxy.Type.HTTP,
                new InetSocketAddress(InetAddress.getLoopbackAddress(), server.getLocalPort()));
    }

    int port() {
        return server.getLocalPort();
    }

    private void acceptLoop() {
        while (!closed) {
            try {
                Socket client = server.accept();
                pool.execute(() -> handle(client));
            } catch (IOException e) {
                if (!closed) {
                    log.error("Bridge accept failed: {}", e.toString());
                }
                return;
            }
        }
    }

    private void handle(Socket client) {
        Socket upstream = null;
        try (client) {
            client.setSoTimeout(HEAD_READ_TIMEOUT_MS);
            client.setTcpNoDelay(true);
            InputStream in = new BufferedInputStream(client.getInputStream());
            OutputStream out = client.getOutputStream();

            String head = readHead(in);
            String requestLine = head.lines().findFirst().orElse("");
            String[] parts = requestLine.split(" ");
            if (parts.length < 3 || !"CONNECT".equalsIgnoreCase(parts[0])) {
                log.warn("Rejecting non-CONNECT request through SOCKS bridge: '{}'", abbreviate(requestLine));
                respond(out, "405 Method Not Allowed", "Allow: CONNECT\r\n",
                        "Only HTTPS (CONNECT) is supported through a SOCKS tunnel.");
                return;
            }

            String authority = parts[1];
            int colon = authority.lastIndexOf(':');
            if (colon <= 0 || colon == authority.length() - 1) {
                respond(out, "400 Bad Request", "", "Malformed CONNECT authority");
                return;
            }
            String host = authority.substring(0, colon);
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            int port;
            try {
                port = Integer.parseInt(authority.substring(colon + 1));
            } catch (NumberFormatException e) {
                respond(out, "400 Bad Request", "", "Malformed CONNECT port");
                return;
            }
            if (port < 1 || port > 65_535) {
                respond(out, "400 Bad Request", "", "CONNECT port out of range");
                return;
            }
            if (!config.matches(host)) {
                log.warn("Refusing CONNECT to {} (outside target domain {})", host, config.targetDomain());
                respond(out, "403 Forbidden", "", "Host is not inside the tunnelled domain");
                return;
            }

            try {
                upstream = new Socket(new Proxy(Proxy.Type.SOCKS, config.proxyAddress()));
                // Unresolved => the SOCKS5 server resolves the name (remote DNS).
                upstream.connect(InetSocketAddress.createUnresolved(host, port), UPSTREAM_CONNECT_TIMEOUT_MS);
                upstream.setTcpNoDelay(true);
            } catch (IOException e) {
                log.warn("SOCKS connect to {}:{} via {}:{} failed: {}", host, port,
                        config.proxyHost(), config.proxyPort(), e.getMessage());
                closeQuietly(upstream);
                respond(out, "502 Bad Gateway", "", "SOCKS connect failed: " + e.getMessage());
                return;
            }

            out.write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            out.flush();
            client.setSoTimeout(0);
            log.debug("Tunnel open: {}:{}", host, port);

            Socket up = upstream;
            pool.execute(() -> pipe(in, up, "client->upstream"));
            pipe(up, client, "upstream->client");
        } catch (SocketTimeoutException e) {
            log.debug("Client sent no request head in time");
        } catch (IOException e) {
            log.debug("Bridge connection ended: {}", e.toString());
        } finally {
            closeQuietly(upstream);
        }
    }

    private static void pipe(InputStream from, Socket to, String label) {
        try {
            from.transferTo(to.getOutputStream());
        } catch (IOException e) {
            log.trace("{} pipe ended: {}", label, e.toString());
        } finally {
            closeQuietly(to); // tears down both directions
        }
    }

    private static void pipe(Socket from, Socket to, String label) {
        try {
            pipe(from.getInputStream(), to, label);
        } catch (IOException e) {
            closeQuietly(to);
        }
    }

    /** Reads up to and including the blank line that ends the request head; consumes nothing more. */
    private static String readHead(InputStream in) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream(256);
        int state = 0; // matches \r\n\r\n
        int b;
        while ((b = in.read()) != -1) {
            buf.write(b);
            if (buf.size() > MAX_HEAD_BYTES) {
                throw new IOException("Request head too large");
            }
            state = switch (state) {
                case 0, 2 -> b == '\r' ? state + 1 : 0;
                case 1, 3 -> b == '\n' ? state + 1 : (b == '\r' ? 1 : 0);
                default -> 0;
            };
            if (state == 4) {
                return buf.toString(StandardCharsets.ISO_8859_1);
            }
        }
        throw new IOException("Connection closed before request head completed");
    }

    private static void respond(OutputStream out, String status, String extraHeaders, String message)
            throws IOException {
        byte[] body = (message + "\n").getBytes(StandardCharsets.UTF_8);
        String head = "HTTP/1.1 " + status + "\r\n" + extraHeaders
                + "Content-Type: text/plain; charset=utf-8\r\n"
                + "Content-Length: " + body.length + "\r\n"
                + "Connection: close\r\n\r\n";
        out.write(head.getBytes(StandardCharsets.US_ASCII));
        out.write(body);
        out.flush();
    }

    private static String abbreviate(String s) {
        return s.length() <= 120 ? s : s.substring(0, 120) + "...";
    }

    private static void closeQuietly(Socket s) {
        if (s != null) {
            try {
                s.close();
            } catch (IOException ignored) {
                // nothing useful to do
            }
        }
    }

    @Override
    public void close() {
        closed = true;
        try {
            server.close();
        } catch (IOException ignored) {
            // already closing
        }
        pool.shutdownNow();
    }

    /**
     * Supplies SOCKS5 username/password to the JDK's SOCKS implementation, which asks the
     * JVM-wide default {@link Authenticator}. Only answers for the configured SOCKS proxy port.
     */
    private static final class SocksCredentials extends Authenticator {
        private final int proxyPort;
        private final String user;
        private final char[] pass;

        private SocksCredentials(TunnelConfig c) {
            this.proxyPort = c.proxyPort();
            this.user = c.proxyUsername();
            this.pass = c.proxyPassword().toCharArray();
        }

        static void install(TunnelConfig c) {
            Authenticator.setDefault(new SocksCredentials(c));
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            String proto = getRequestingProtocol();
            if (proto != null && proto.toUpperCase(java.util.Locale.ROOT).startsWith("SOCKS")
                    && getRequestingPort() == proxyPort) {
                return new PasswordAuthentication(user, pass.clone());
            }
            return null;
        }
    }
}
