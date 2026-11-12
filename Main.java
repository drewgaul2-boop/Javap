package com.example.selectivetunnel;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Demo: one request to the target domain (through the proxy) and one to an external site (direct).
 *
 * <p>Configuration (system properties, e.g. {@code mvn compile exec:java -Dtunnel.targetDomain=example.com}):
 * <pre>
 *   tunnel.targetDomain     default example.com
 *   tunnel.targetUrl        default https://&lt;targetDomain&gt;
 *   tunnel.externalUrl      default https://httpbin.org/get
 *   tunnel.proxy.host       default 127.0.0.1
 *   tunnel.proxy.port       default 1080
 *   tunnel.proxy.type       SOCKS (default) | HTTP
 *   tunnel.proxy.username   optional   (or env TUNNEL_PROXY_USERNAME)
 *   tunnel.proxy.password   optional   (or env TUNNEL_PROXY_PASSWORD)
 * </pre>
 */
public final class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

    private Main() {
    }

    public static void main(String[] args) {
        int exit = 0;
        try {
            TunnelConfig config = TunnelConfig.fromSystemProperties();
            String targetUrl = System.getProperty("tunnel.targetUrl", "https://" + config.targetDomain());
            String externalUrl = System.getProperty("tunnel.externalUrl", "https://httpbin.org/get");

            try (SelectiveHttpClient http = new SelectiveHttpClient(config)) {
                boolean proxyUp = isProxyReachable(config);
                if (!proxyUp) {
                    log.error("""
                            Proxy {}:{} ({}) is not reachable. Start it first, e.g.:
                                ssh -D {} -N user@remote-server
                            Requests to {} will be skipped; direct traffic still works.""",
                            config.proxyHost(), config.proxyPort(), config.proxyType(),
                            config.proxyPort(), config.targetDomain());
                    exit = 1;
                }

                System.out.println("=== 1) Target domain (expected: via proxy) ===");
                if (proxyUp) {
                    exit |= run(http, targetUrl);
                } else {
                    System.out.println("SKIPPED: proxy not reachable at "
                            + config.proxyHost() + ":" + config.proxyPort());
                }

                System.out.println();
                System.out.println("=== 2) External site (expected: direct) ===");
                exit |= run(http, externalUrl);
            }
        } catch (IllegalArgumentException | IllegalStateException e) {
            log.error("Configuration error: {}", e.getMessage());
            exit = 2;
        } catch (RuntimeException e) {
            log.error("Unexpected failure", e);
            exit = 3;
        }
        if (exit != 0) {
            System.exit(exit);
        }
    }

    /** Performs one GET and prints a summary. Returns 0 on success, 1 on failure. */
    private static int run(SelectiveHttpClient http, String url) {
        try {
            TunnelResponse r = http.get(url);
            System.out.printf("URL        : %s%n", r.uri());
            System.out.printf("Proxy used : %s%n", r.proxyUsed());
            System.out.printf("Status     : %d%n", r.statusCode());
            System.out.printf("Content-Type: %s%n", r.headers().getOrDefault("content-type", java.util.List.of("?")));
            System.out.printf("Elapsed    : %d ms%n", r.elapsed().toMillis());
            String body = r.body() == null ? "" : r.body();
            System.out.printf("Body       : %s%s%n", body.substring(0, Math.min(300, body.length())),
                    body.length() > 300 ? "..." : "");
            return 0;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.out.println("INTERRUPTED: " + url);
            return 1;
        } catch (IOException e) {
            String hint = http.wouldUseProxy(url)
                    ? " (this request goes through the proxy: check the tunnel and that the proxy can reach the site)"
                    : "";
            String reason = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            log.error("Request to {} failed: {}{}", url, reason, hint);
            System.out.println("FAILED: " + url + " -> " + reason);
            return 1;
        } catch (IllegalArgumentException e) {
            log.error("Bad request: {}", e.getMessage());
            System.out.println("FAILED: " + e.getMessage());
            return 1;
        }
    }

    private static boolean isProxyReachable(TunnelConfig config) {
        try (Socket s = new Socket()) {
            s.connect(new InetSocketAddress(config.proxyHost(), config.proxyPort()), 2_000);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
}
