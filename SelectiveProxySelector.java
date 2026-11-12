package com.example.selectivetunnel;

import java.io.IOException;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Returns the tunnel proxy for the target domain (and its subdomains) and {@link Proxy#NO_PROXY}
 * for everything else.
 *
 * <p>Note: {@code java.net.http.HttpClient} only honours {@code Proxy.Type.HTTP} entries and treats
 * SOCKS entries as direct connections. {@link SelectiveHttpClient} therefore passes an
 * <em>effective</em> proxy to this selector (an HTTP proxy pointing at a local SOCKS bridge when the
 * configured proxy is SOCKS). Plain {@code Socket}/{@code HttpURLConnection} users can use the
 * single-argument constructor, which hands out the configured proxy as-is.
 */
public final class SelectiveProxySelector extends ProxySelector {

    private static final Logger log = LoggerFactory.getLogger(SelectiveProxySelector.class);

    private final TunnelConfig config;
    private final Proxy proxy;

    /** Uses the configured proxy exactly as configured. */
    public SelectiveProxySelector(TunnelConfig config) {
        this(config, new Proxy(config.proxyType(), config.proxyAddress()));
    }

    /** Uses {@code effectiveProxy} for matching requests (see class comment). */
    public SelectiveProxySelector(TunnelConfig config, Proxy effectiveProxy) {
        this.config = Objects.requireNonNull(config, "config");
        this.proxy = Objects.requireNonNull(effectiveProxy, "effectiveProxy");
    }

    @Override
    public List<Proxy> select(URI uri) {
        if (uri == null) {
            throw new IllegalArgumentException("uri must not be null"); // contract of ProxySelector
        }
        if (wouldUseProxy(uri)) {
            log.debug("{} -> proxy {}", uri, proxy);
            return List.of(proxy);
        }
        log.debug("{} -> direct", uri);
        return List.of(Proxy.NO_PROXY);
    }

    /** Side-effect-free routing decision, also used to report whether a response was proxied. */
    public boolean wouldUseProxy(URI uri) {
        return config.matches(uri.getHost());
    }

    @Override
    public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
        log.warn("Proxy connection failed: uri={}, proxyAddress={}, error={}: {}",
                uri, sa, ioe == null ? "n/a" : ioe.getClass().getSimpleName(),
                ioe == null ? "n/a" : ioe.getMessage());
    }
}
