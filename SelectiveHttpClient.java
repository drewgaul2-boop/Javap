package com.example.selectivetunnel;

import java.io.IOException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.Proxy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * {@link HttpClient} wrapper that tunnels only the target domain through the configured proxy.
 *
 * <ul>
 *   <li>HTTP proxy: handed to {@code HttpClient} directly (with proxy authentication if configured).</li>
 *   <li>SOCKS5 proxy: {@code HttpClient} cannot speak SOCKS, so a loopback {@link SocksConnectBridge}
 *       is started and presented to {@code HttpClient} as an HTTP proxy. Only {@code https://} targets
 *       can be tunnelled this way.</li>
 * </ul>
 */
public final class SelectiveHttpClient implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(SelectiveHttpClient.class);

    static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    private final TunnelConfig config;
    private final SelectiveProxySelector selector;
    private final HttpClient client;
    private final SocksConnectBridge bridge; // null unless proxyType == SOCKS

    public SelectiveHttpClient(TunnelConfig config) {
        this.config = Objects.requireNonNull(config, "config");

        // The JDK refuses Basic auth on CONNECT tunnels by default; allow it for authenticated HTTP
        // proxies. Must be set before the first HttpClient is created in this JVM.
        if (config.proxyType() == Proxy.Type.HTTP && config.hasCredentials()
                && System.getProperty("jdk.http.auth.tunneling.disabledSchemes") == null) {
            System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
        }

        Proxy effective;
        if (config.proxyType() == Proxy.Type.SOCKS) {
            try {
                this.bridge = new SocksConnectBridge(config);
            } catch (IOException e) {
                throw new IllegalStateException("Could not start local SOCKS bridge", e);
            }
            effective = bridge.asHttpProxy();
        } else {
            this.bridge = null;
            effective = new Proxy(Proxy.Type.HTTP, config.proxyAddress());
        }
        this.selector = new SelectiveProxySelector(config, effective);

        SSLParameters ssl = new SSLParameters();
        ssl.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"}); // prefer 1.3, allow 1.2 fallback
        SSLContext ctx;
        try {
            ctx = SSLContext.getDefault();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("No default SSLContext available", e);
        }

        HttpClient.Builder builder = HttpClient.newBuilder()
                .proxy(selector)
                .connectTimeout(CONNECT_TIMEOUT)
                .followRedirects(HttpClient.Redirect.NORMAL)
                .sslContext(ctx)
                .sslParameters(ssl);
        if (config.proxyType() == Proxy.Type.HTTP && config.hasCredentials()) {
            builder.authenticator(new ProxyAuthenticator(config));
        }
        this.client = builder.build();
        log.info("Selective client ready: {}", config);
    }

    public TunnelConfig config() {
        return config;
    }

    /** Whether a request to {@code url} would be sent through the tunnel proxy. */
    public boolean wouldUseProxy(String url) {
        return selector.wouldUseProxy(URI.create(url));
    }

    public TunnelResponse get(String url) throws IOException, InterruptedException {
        HttpRequest request = baseRequest(url).GET().build();
        return send(request);
    }

    public TunnelResponse post(String url, String jsonBody) throws IOException, InterruptedException {
        HttpRequest request = baseRequest(url)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonBody == null ? "" : jsonBody))
                .build();
        return send(request);
    }

    private HttpRequest.Builder baseRequest(String url) {
        URI uri = URI.create(Objects.requireNonNull(url, "url"));
        String scheme = uri.getScheme();
        if (uri.getHost() == null || scheme == null
                || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Only absolute http(s) URLs are supported: " + url);
        }
        if (config.proxyType() == Proxy.Type.SOCKS && scheme.equalsIgnoreCase("http")
                && selector.wouldUseProxy(uri)) {
            throw new IllegalArgumentException(
                    "Plain http:// to the tunnelled domain is not supported over SOCKS (use https://): " + url);
        }
        return HttpRequest.newBuilder(uri)
                .timeout(REQUEST_TIMEOUT)
                .header("User-Agent", "selective-tunnel/1.0");
    }

    private TunnelResponse send(HttpRequest request) throws IOException, InterruptedException {
        boolean proxied = selector.wouldUseProxy(request.uri());
        Instant start = Instant.now();
        log.info("{} {} ({})", request.method(), request.uri(), proxied ? "via proxy" : "direct");
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        Duration elapsed = Duration.between(start, Instant.now());
        log.info("{} {} -> {} in {} ms", request.method(), request.uri(), response.statusCode(), elapsed.toMillis());
        return new TunnelResponse(request.uri(), response.statusCode(), response.headers().map(),
                response.body(), proxied, elapsed);
    }

    /** Stops the local SOCKS bridge, if any. */
    @Override
    public void close() {
        if (bridge != null) {
            bridge.close();
        }
    }

    /** Answers 407 proxy challenges, and only for the configured proxy. */
    private static final class ProxyAuthenticator extends Authenticator {
        private final TunnelConfig config;

        ProxyAuthenticator(TunnelConfig config) {
            this.config = config;
        }

        @Override
        protected PasswordAuthentication getPasswordAuthentication() {
            if (getRequestorType() == RequestorType.PROXY
                    && getRequestingPort() == config.proxyPort()
                    && config.proxyHost().equalsIgnoreCase(getRequestingHost())) {
                return new PasswordAuthentication(config.proxyUsername(), config.proxyPassword().toCharArray());
            }
            return null;
        }
    }
}
