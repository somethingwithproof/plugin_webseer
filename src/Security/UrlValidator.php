<?php

declare(strict_types=1);

namespace PluginWebseer\Security;

/**
 * Guards against SSRF by classifying URLs before the cURL class fetches them.
 *
 * The existing code in includes/functions.php and classes/cURL.php accepts any
 * URL stored in plugin_webseer_urls.url without host-range validation. An
 * authenticated admin can therefore target internal infrastructure.
 *
 * This class provides the seam needed for TDD — tests import isInternalHost()
 * via the ->todo() annotations until the legacy code is wired to call it.
 */
final class UrlValidator
{
    private const ALLOWED_SCHEMES = ['http', 'https'];

    /**
     * RFC-1918 and link-local blocks that must never be checked by the poller.
     * Expressed as [network_long, mask_long] pairs for fast integer comparison.
     *
     * @var list<array{int, int}>
     */
    private const PRIVATE_RANGES = [
        [0x0A000000, 0xFF000000], // 10.0.0.0/8
        [0xAC100000, 0xFFF00000], // 172.16.0.0/12
        [0xC0A80000, 0xFFFF0000], // 192.168.0.0/16
        [0x7F000000, 0xFF000000], // 127.0.0.0/8  (loopback)
        [0xA9FE0000, 0xFFFF0000], // 169.254.0.0/16 (link-local / AWS metadata)
        [0x00000000, 0xFF000000], // 0.0.0.0/8
    ];

    public function isAllowed(string $url): bool
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!is_string($scheme) || !in_array(strtolower($scheme), self::ALLOWED_SCHEMES, true)) {
            return false;
        }

        $host = parse_url($url, PHP_URL_HOST);
        if (!is_string($host) || $host === '') {
            return false;
        }

        // Strip IPv6 brackets.
        $host = ltrim(rtrim($host, ']'), '[');

        return !$this->isInternalHost($host);
    }

    /**
     * Returns true if $host resolves to or IS a private/loopback address.
     * Intentionally conservative: resolution failures are treated as internal.
     */
    public function isInternalHost(string $host): bool
    {
        if ($host === '' || $host === 'localhost') {
            return true;
        }

        // IPv6 loopback / link-local.
        if (strpos($host, ':') !== false) {
            return $this->isInternalIPv6($host);
        }

        $ip = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        if ($ip === false) {
            // It's a hostname — resolve to IPv4.
            $resolved = gethostbyname($host);
            if ($resolved === $host) {
                // Resolution failed; block to be safe.
                return true;
            }
            $ip = $resolved;
        }

        $long = ip2long($ip);
        if ($long === false) {
            return true;
        }

        foreach (self::PRIVATE_RANGES as [$network, $mask]) {
            if (($long & $mask) === $network) {
                return true;
            }
        }

        return false;
    }

    private function isInternalIPv6(string $host): bool
    {
        // ::1 loopback
        if ($host === '::1') {
            return true;
        }
        // fe80::/10 link-local
        if (stripos($host, 'fe80') === 0) {
            return true;
        }
        // fc00::/7 unique local
        $first16 = hexdec(substr(str_replace(':', '', $host), 0, 4));
        if (($first16 & 0xFE00) === 0xFC00) {
            return true;
        }
        return false;
    }
}

/**
 * Module-level shim so test files can call isInternalHost() as a bare function
 * until the production code is wired to use UrlValidator directly.
 */
function isInternalHost(string $host): bool
{
    return (new UrlValidator())->isInternalHost($host);
}
