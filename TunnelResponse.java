package com.example.selectivetunnel;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * Structured result of a request made by {@link SelectiveHttpClient}.
 *
 * @param uri        the requested URI
 * @param statusCode HTTP status code
 * @param headers    response headers (case-insensitive keys)
 * @param body       response body as text
 * @param proxyUsed  whether the routing decision for this request was "through the tunnel proxy"
 * @param elapsed    wall-clock time for the exchange
 */
public record TunnelResponse(
        URI uri,
        int statusCode,
        Map<String, List<String>> headers,
        String body,
        boolean proxyUsed,
        Duration elapsed) {

    public boolean isSuccessful() {
        return statusCode >= 200 && statusCode < 300;
    }
}
