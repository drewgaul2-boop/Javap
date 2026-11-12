package com.example.selectivetunnel;

import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Locale;
import java.util.Objects;

/**
 * Immutable configuration for the selective tunnel.
 *
 * @param targetDomain  domain whose traffic goes through the proxy. Accepts {@code example.com},
 *                      {@code https://example.com/path}, {@code ://example.com}, {@code *.example.com};
 *                      it is normalised to a bare lower-case host name. Subdomains match too.
 * @param proxyHost     proxy host name or IP
 * @param proxyPort     proxy port (1-65535)
 * @param proxyType     {@link Proxy.Type#SOCKS} (SOCKS5) or {@link Proxy.Type#HTTP}
 * @param proxyUsername optional proxy username ({@code null} or blank for none)
 * @param proxyPassword optional proxy password
 */
public record TunnelConfig(
        String targetDomain,
        String proxyHost,
        int proxyPort,
        Proxy.Type proxyType,
        String proxyUsername,
        String proxyPassword) {

    public TunnelConfig {
        targetDomain = normalizeDomain(targetDomain);
        if (proxyHost == null || proxyHost.isBlank()) {
            throw new IllegalArgumentException("proxyHost must not be blank");
        }
        proxyHost = proxyHost.trim();
        if (proxyPort < 1 || proxyPort > 65_535) {
            throw new IllegalArgumentException("proxyPort out of range: " + proxyPort);
        }
        Objects.requireNonNull(proxyType, "proxyType");
        if (proxyType != Proxy.Type.SOCKS && proxyType != Proxy.Type.HTTP) {
            throw new IllegalArgumentException("proxyType must be SOCKS or HTTP, was " + proxyType);
        }
        if (proxyUsername != null && proxyUsername.isBlank()) {
            proxyUsername = null;
        }
        if (proxyUsername == null) {
            proxyPassword = null;
        }
    }

    /** Config without proxy credentials. */
    public TunnelConfig(String targetDomain, String proxyHost, int proxyPort, Proxy.Type proxyType) {
        this(targetDomain, proxyHost, proxyPort, proxyType, null, null);
    }

    /**
     * Reads configuration from system properties, falling back to environment variables for secrets:
     * {@code tunnel.targetDomain}, {@code tunnel.proxy.host}, {@code tunnel.proxy.port},
     * {@code tunnel.proxy.type} (SOCKS|HTTP), {@code tunnel.proxy.username},
     * {@code tunnel.proxy.password} (or env {@code TUNNEL_PROXY_PASSWORD}).
     */
    public static TunnelConfig fromSystemProperties() {
        String password = System.getProperty("tunnel.proxy.password", System.getenv("TUNNEL_PROXY_PASSWORD"));
        return new TunnelConfig(
                System.getProperty("tunnel.targetDomain", "example.com"),
                System.getProperty("tunnel.proxy.host", "127.0.0.1"),
                Integer.parseInt(System.getProperty("tunnel.proxy.port", "1080")),
                Proxy.Type.valueOf(System.getProperty("tunnel.proxy.type", "SOCKS").toUpperCase(Locale.ROOT)),
                System.getProperty("tunnel.proxy.username", System.getenv("TUNNEL_PROXY_USERNAME")),
                password);
    }

    public boolean hasCredentials() {
        return proxyUsername != null && proxyPassword != null;
    }

    /** Unresolved proxy address (resolution happens at connect time). */
    public InetSocketAddress proxyAddress() {
        return InetSocketAddress.createUnresolved(proxyHost, proxyPort);
    }

    /** True if {@code host} equals the target domain or is a subdomain of it. */
    public boolean matches(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        String h = host.toLowerCase(Locale.ROOT);
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        return h.equals(targetDomain) || h.endsWith("." + targetDomain);
    }

    /** Reduces user input such as {@code "://Example.com:443/x"} to {@code "example.com"}. */
    static String normalizeDomain(String input) {
        if (input == null || input.isBlank()) {
            throw new IllegalArgumentException("targetDomain must not be blank");
        }
        String s = input.trim().toLowerCase(Locale.ROOT);
        int scheme = s.indexOf("://");
        if (scheme >= 0) {
            s = s.substring(scheme + 3);
        }
        int end = s.length();
        for (char c : new char[] {'/', '?', '#'}) {
            int i = s.indexOf(c);
            if (i >= 0) {
                end = Math.min(end, i);
            }
        }
        s = s.substring(0, end);
        int at = s.lastIndexOf('@');
        if (at >= 0) {
            s = s.substring(at + 1);
        }
        int colon = s.lastIndexOf(':');
        if (colon >= 0 && s.indexOf(']') < colon) { // strip :port, keep IPv6 literals intact
            s = s.substring(0, colon);
        }
        while (s.startsWith("*.") || s.startsWith(".")) {
            s = s.substring(s.startsWith("*.") ? 2 : 1);
        }
        while (s.endsWith(".")) {
            s = s.substring(0, s.length() - 1);
        }
        if (s.isEmpty()) {
            throw new IllegalArgumentException("targetDomain has no host part: '" + input + "'");
        }
        return s;
    }

    /** Never prints the password. */
    @Override
    public String toString() {
        return "TunnelConfig[targetDomain=" + targetDomain
                + ", proxy=" + proxyType + "://" + proxyHost + ":" + proxyPort
                + ", auth=" + (hasCredentials() ? "yes(" + proxyUsername + ")" : "no") + "]";
    }
}
