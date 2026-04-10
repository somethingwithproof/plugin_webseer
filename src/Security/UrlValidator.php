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

        // Direct IPv4 literal.
        $ipv4 = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
        if ($ipv4 !== false) {
            return $this->isInternalIPv4($ipv4);
        }

        // Direct IPv6 literal (normalize via inet_pton).
        $ipv6 = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
        if ($ipv6 !== false) {
            return $this->isInternalIPv6($ipv6);
        }

        // Hostname: resolve both A and AAAA records.
        $addresses = $this->resolveHost($host);
        if (empty($addresses)) {
            // Resolution failed; block to be safe.
            return true;
        }

        foreach ($addresses as $addr) {
            if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
                if ($this->isInternalIPv4($addr)) {
                    return true;
                }
            } elseif (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                if ($this->isInternalIPv6($addr)) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * @return list<string>
     */
    private function resolveHost(string $host): array
    {
        $addresses = [];

        $a = @dns_get_record($host, DNS_A);
        if (is_array($a)) {
            foreach ($a as $rec) {
                if (isset($rec['ip'])) {
                    $addresses[] = $rec['ip'];
                }
            }
        }

        $aaaa = @dns_get_record($host, DNS_AAAA);
        if (is_array($aaaa)) {
            foreach ($aaaa as $rec) {
                if (isset($rec['ipv6'])) {
                    $addresses[] = $rec['ipv6'];
                }
            }
        }

        // Fallback to gethostbynamel for IPv4 if dns_get_record returned nothing.
        if (empty($addresses)) {
            $legacy = gethostbynamel($host);
            if (is_array($legacy)) {
                $addresses = $legacy;
            }
        }

        return $addresses;
    }

    private function isInternalIPv4(string $ip): bool
    {
        $long = ip2long($ip);
        if ($long === false) {
            return true;
        }
        // ip2long returns a signed int on 32-bit systems; coerce to unsigned comparison.
        $long &= 0xFFFFFFFF;

        foreach (self::PRIVATE_RANGES as [$network, $mask]) {
            if (($long & $mask) === $network) {
                return true;
            }
        }

        return false;
    }

    private function isInternalIPv6(string $host): bool
    {
        $binary = @inet_pton($host);
        if ($binary === false || strlen($binary) !== 16) {
            // Malformed IPv6 — block to be safe.
            return true;
        }

        // ::1 loopback (all zeros except last byte = 1).
        if ($binary === str_repeat("\x00", 15) . "\x01") {
            return true;
        }

        // :: unspecified.
        if ($binary === str_repeat("\x00", 16)) {
            return true;
        }

        $firstByte = ord($binary[0]);
        $secondByte = ord($binary[1]);

        // fe80::/10 link-local: first 10 bits = 1111111010
        if ($firstByte === 0xFE && ($secondByte & 0xC0) === 0x80) {
            return true;
        }

        // fc00::/7 unique local: first 7 bits = 1111110
        if (($firstByte & 0xFE) === 0xFC) {
            return true;
        }

        // IPv4-mapped IPv6 (::ffff:a.b.c.d): check underlying IPv4.
        if (substr($binary, 0, 10) === str_repeat("\x00", 10) && substr($binary, 10, 2) === "\xFF\xFF") {
            $ipv4 = sprintf('%d.%d.%d.%d', ord($binary[12]), ord($binary[13]), ord($binary[14]), ord($binary[15]));
            return $this->isInternalIPv4($ipv4);
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
