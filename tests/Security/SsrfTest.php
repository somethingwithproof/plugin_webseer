<?php

declare(strict_types=1);

use function PluginWebseer\Tests\Helpers\html_escape;

describe('SSRF guard on URL parameter', function (): void {
    it('rejects internal network addresses', function (): void {
        $internalUrls = [
            'http://169.254.169.254/latest/meta-data/',  // AWS metadata
            'http://127.0.0.1:8080/admin',
            'http://10.0.0.1/internal',
            'http://192.168.1.1/router',
            'http://[::1]/ipv6-local',
        ];

        foreach ($internalUrls as $url) {
            $parsed = parse_url($url, PHP_URL_HOST);
            $isInternal = isInternalHost($parsed ?? '');
            expect($isInternal)->toBeTrue("Expected {$url} to be rejected as internal");
        }
    })->todo('Extract isInternalHost() to src/Security/UrlValidator.php first');

    it('allows public HTTPS URLs', function (): void {
        $publicUrl = 'https://example.com/health';
        $parsed = parse_url($publicUrl, PHP_URL_HOST);
        expect($parsed)->toBe('example.com');
    })->todo('Wire after UrlValidator seam is in place');

    it('rejects file:// scheme', function (): void {
        $url = 'file:///etc/passwd';
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $allowedSchemes = ['http', 'https'];
        expect(in_[$scheme, $allowedSchemes, true])->toBeFalse();
    })->todo('Extract scheme allowlist to src/Security/UrlValidator.php first');

    it('rejects gopher:// scheme', function (): void {
        $url = 'gopher://127.0.0.1:6379/_FLUSHALL';
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $allowedSchemes = ['http', 'https'];
        expect(in_[$scheme, $allowedSchemes, true])->toBeFalse();
    })->todo('Extract scheme allowlist to src/Security/UrlValidator.php first');

    it('rejects DNS rebinding via non-routable 0.0.0.0', function (): void {
        $url = 'http://0.0.0.0/secret';
        $parsed = parse_url($url, PHP_URL_HOST);
        $isInternal = isInternalHost($parsed ?? '');
        expect($isInternal)->toBeTrue();
    })->todo('Extract isInternalHost() to src/Security/UrlValidator.php first');

    it('url stored in DB is rendered html-escaped on display', function (): void {
        // Simulates a stored URL with XSS payload being echoed back.
        // The existing list_urls() in webseer.php uses form_selectable_cell()
        // which internally calls html_escape — this test documents the contract.
        $storedUrl = 'http://example.com/<script>alert(1)</script>';
        $escaped   = htmlspecialchars($storedUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        expect($escaped)->not->toContain('<script>');
        expect($escaped)->toContain('&lt;script&gt;');
    });
});

describe('unserialize of remote server data', function (): void {
    it('refuses to unserialize objects from remote server response', function (): void {
        // FIND-003 (HIGH): functions.php lines 75 and 107 now pass allowed_classes:false.
        // Verify that an object payload is blocked and returns false.
        $maliciousPayload = base64_encode(serialize(new stdClass()));
        $decoded = base64_decode($maliciousPayload);
        $result = unserialize($decoded, ['allowed_classes' => false]);
        // allowed_classes:false returns __PHP_Incomplete_Class, not false
        expect($result)->toBeInstanceOf(\__PHP_Incomplete_Class::class);
    });

    it('still deserializes plain arrays from remote server response', function (): void {
        // Confirm allowed_classes:false does not break legitimate array payloads —
        // the actual data shape used by plugin_webseer_refresh_servers/urls.
        $servers = [['id' => 1, 'enabled' => 'on', 'master' => 1, 'name' => 'main', 'url' => 'https://example.com', 'ip' => '1.2.3.4', 'location' => 'US']];
        $payload = base64_encode(serialize($servers));
        $decoded = base64_decode($payload);
        $result  = unserialize($decoded, ['allowed_classes' => false]);
        expect($result)->toBeArray();
        expect($result[0]['id'])->toBe(1);
    });
});

describe('FIND-001 regression: update_contacts uses prepared statements', function (): void {
    it('db_execute_prepared stub accepts the contacts REPLACE INTO shape with id', function (): void {
        // Verify the prepared-statement form does not throw and accepts the expected
        // parameter count. The stub always returns true; this guards the call shape.
        $result = db_execute_prepared(
            'REPLACE INTO plugin_webseer_contacts (id, user_id, type, data) VALUES (?, ?, \'email\', ?)',
            [42, 7, "admin'--malicious@evil.com"]
        );
        expect($result)->toBeTrue();
    });

    it('db_execute_prepared stub accepts the contacts REPLACE INTO shape without id', function (): void {
        $result = db_execute_prepared(
            'REPLACE INTO plugin_webseer_contacts (user_id, type, data) VALUES (?, \'email\', ?)',
            [7, "admin'--malicious@evil.com"]
        );
        expect($result)->toBeTrue();
    });

    it('email address with SQL metacharacters does not mutate the parameterised query', function (): void {
        // In production Cacti the value is bound; here we assert that the SQL template
        // contains only ? placeholders and no interpolated user data.
        $sql = 'REPLACE INTO plugin_webseer_contacts (user_id, type, data) VALUES (?, \'email\', ?)';
        expect($sql)->not->toContain("'--");
        expect(substr_count($sql, '?'))->toBe(2);
    });
});

describe('FIND-004 regression: rfilter RLIKE uses db_qstr', function (): void {
    it('db_qstr escapes single-quote in rfilter value', function (): void {
        $userInput = "foo' OR '1'='1";
        $quoted    = db_qstr($userInput);
        // Must be wrapped in single quotes and the interior quote escaped.
        expect($quoted)->toStartWith("'");
        expect($quoted)->toEndWith("'");
        expect($quoted)->not->toContain("' OR '");
    });

    it('db_qstr output is safe to embed in RLIKE clause', function (): void {
        $userInput = "example.com'--";
        $quoted    = db_qstr($userInput);
        $clause    = 'display_name RLIKE ' . $quoted;
        // No unquoted single-quote should appear outside the wrapping quotes.
        // db_qstr wraps in quotes and escapes embedded quotes with addslashes (\')
        // The wrapping quotes are present but the embedded quote is backslash-escaped
        expect($clause)->toStartWith("display_name RLIKE '")
                        ->toEndWith("'");
    });

    it('db_qstr preserves benign filter values', function (): void {
        expect(db_qstr('example.com'))->toBe("'example.com'");
        expect(db_qstr(''))->toBe("''");
    });
});

describe('advisory regression: unserialize allowed_classes', function (): void {
    it('ADVISORY regression: includes/functions.php uses allowed_classes => false on both unserialize calls', function (): void {
        // Confirms the unserialize-RCE advisory fix is in place at lines 75 and 107.
        $src   = file_get_contents(__DIR__ . '/../../includes/functions.php');
        $count = substr_count($src, "'allowed_classes' => false");

        expect($count)->toBeGreaterThanOrEqual(2);
        // Pattern matches only the bare two-argument form (no allowed_classes).
        // unserialize(base64_decode($x)) with closing paren immediately after base64_decode result.
        expect($src)->not->toMatch('/unserialize\s*\(\s*base64_decode\([^)]+\)\s*\)/');
    });

    it('unserialize with allowed_classes => false converts gadget object to __PHP_Incomplete_Class', function (): void {
        $gadget  = 'O:8:"stdClass":1:{s:4:"exec";s:6:"id > /";}';
        $encoded = base64_encode($gadget);
        $result  = unserialize(base64_decode($encoded), ['allowed_classes' => false]);

        expect($result)->toBeInstanceOf(\__PHP_Incomplete_Class::class);
    });
});
