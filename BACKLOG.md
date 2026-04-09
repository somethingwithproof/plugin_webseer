# plugin_webseer — Backlog

---

### Issue #1: security(sql): parameterise email address in plugin_webseer_update_contacts()
- **Priority**: high
- **Labels**: [security, sql-injection, hardening]
- **Branch**: `security/1-parameterise-contacts-email`
- **Evidence**: `includes/functions.php:319-325` — `db_execute("REPLACE INTO plugin_webseer_contacts ... '" . $u['email_address'] . "'")`
- **Acceptance criteria**:
  - [ ] Both `db_execute()` calls replaced with `db_execute_prepared()` using `?` placeholders
  - [ ] `$u['id']`, `$cid`, and `$u['email_address']` all bound as parameters
  - [ ] Unit test covers email address containing single quote
  - [ ] PHPStan level 6 passes
- **Dependencies**: none

---

### Issue #2: security(sql): parameterise rfilter RLIKE clause in list_urls()
- **Priority**: high
- **Labels**: [security, sql-injection, hardening]
- **Branch**: `security/2-parameterise-rfilter-rlike`
- **Evidence**: `webseer.php:744-749` — `'display_name RLIKE \'' . get_request_var('rfilter') . '\''`
- **Acceptance criteria**:
  - [ ] All five RLIKE comparisons use `db_fetch_assoc_prepared()` with bound `?` params
  - [ ] Or `db_qstr()` wrapping applied as interim measure
  - [ ] Regression test with a regex containing a single quote
  - [ ] PHPStan passes
- **Dependencies**: none

---

### Issue #3: security(sql): parameterise proxy filter LIKE clause in proxies()
- **Priority**: high
- **Labels**: [security, sql-injection, hardening]
- **Branch**: `security/3-parameterise-proxy-filter`
- **Evidence**: `webseer_proxies.php:255` — `' name LIKE "%' . get_request_var('filter') . '%" OR hostname LIKE ...'`
- **Acceptance criteria**:
  - [ ] Filter value bound via prepared statement parameter
  - [ ] Test covers filter value with `%`, `_`, `'` characters
- **Dependencies**: none

---

### Issue #4: security(sql): replace manual strip with prepared statement in remote.php SETMASTER
- **Priority**: high
- **Labels**: [security, sql-injection, hardening]
- **Branch**: `security/4-setmaster-prepared`
- **Evidence**: `remote.php:174-176` — `str_replace(array("'", '\\'), '', $_POST['ip'])` then `db_fetch_row("... WHERE ip = '$ip'")`
- **Acceptance criteria**:
  - [ ] `db_fetch_row_prepared('... WHERE ip = ?', [$ip])` replaces the concatenated query
  - [ ] Manual `str_replace` sanitisation removed
  - [ ] Test covers IP containing SQL metacharacters
- **Dependencies**: none

---

### Issue #5: security(ssrf): implement UrlValidator and wire into cURL class
- **Priority**: high
- **Labels**: [security, ssrf, hardening]
- **Branch**: `security/5-ssrf-url-validator`
- **Evidence**: `classes/cURL.php:91,136` — `curl_init($url)` without host validation
- **Acceptance criteria**:
  - [ ] `src/Security/UrlValidator.php` validates scheme allowlist (http/https only)
  - [ ] Blocks RFC-1918, loopback, link-local, AWS metadata ranges
  - [ ] `cURL::get()` calls `UrlValidator::isAllowed()` before `curl_init()`; returns error result on rejection
  - [ ] `cURL::post()` calls `UrlValidator::isAllowed()` before `curl_init()`
  - [ ] All `->todo()` annotations in `SsrfTest.php` converted to passing tests
  - [ ] PHPStan passes
- **Dependencies**: `src/Security/UrlValidator.php` skeleton already present

---

### Issue #6: security(deserialization): replace unserialize with JSON in server sync
- **Priority**: high
- **Labels**: [security, deserialization, hardening]
- **Branch**: `security/6-replace-unserialize-json`
- **Evidence**: `includes/functions.php:75,107` — `unserialize(base64_decode($servers))` / `unserialize(base64_decode($urls))`
- **Acceptance criteria**:
  - [ ] `plugin_webseer_refresh_servers()` and `plugin_webseer_refresh_urls()` decode JSON instead of PHP serialised data
  - [ ] `remote.php` GETSERVERS/GETURLS actions encode with `json_encode()` instead of `serialize()`
  - [ ] If serialised format cannot be changed immediately, at minimum add `['allowed_classes' => false]` to both `unserialize()` calls
  - [ ] Test covers malicious serialised object payload being rejected
- **Dependencies**: #11 (remote.php hardening) for protocol change

---

### Issue #7: security(xss): escape URL in history and list view anchor tags
- **Priority**: high
- **Labels**: [security, xss, hardening]
- **Branch**: `security/7-escape-url-anchor-tags`
- **Evidence**: `webseer.php:651`, `webseer_servers.php:434` — `href='" . $row['url'] . "'"` without `html_escape()`
- **Acceptance criteria**:
  - [ ] Both `$row['url']` occurrences wrapped with `html_escape()`
  - [ ] Scheme validated to be `http` or `https` before rendering as a clickable link; otherwise render as plain text
  - [ ] Test covers URL with `javascript:` scheme and with `<script>` in value
- **Dependencies**: none

---

### Issue #8: security(tls): enable TLS verification by default in cURL class
- **Priority**: medium
- **Labels**: [security, tls, hardening]
- **Branch**: `security/8-tls-verify-default`
- **Evidence**: `classes/cURL.php:192-198` — `CURLOPT_SSL_VERIFYPEER => FALSE` when `checkcert == ''`
- **Acceptance criteria**:
  - [ ] Default behaviour enables peer and host verification
  - [ ] `CURLOPT_CAINFO` set to bundled `ca-bundle.crt`
  - [ ] `checkcert` field inverted: empty = verify (default), explicit flag = skip
  - [ ] Existing service checks that relied on skip-verify prompt admin on upgrade
- **Dependencies**: none

---

### Issue #9: security(ssrf): add SSRF guard to remote.php inter-server POST targets
- **Priority**: medium
- **Labels**: [security, ssrf, hardening]
- **Branch**: `security/9-remote-server-url-guard`
- **Evidence**: `includes/functions.php:68,101,200,207` — `$cc->post($server['url'], ...)` where `$server['url']` is DB-stored
- **Acceptance criteria**:
  - [ ] Server URLs validated through `UrlValidator::isAllowed()` before each POST
  - [ ] Invalid URL logs warning and skips that server
- **Dependencies**: #5

---

### Issue #10: test(harness): bootstrap Pest 4 test harness
- **Priority**: high
- **Labels**: [test, infrastructure]
- **Branch**: `test/10-pest4-bootstrap`
- **Evidence**: no existing test suite
- **Acceptance criteria**:
  - [ ] `composer install` succeeds on PHP 8.4
  - [ ] `vendor/bin/pest` runs and reports 0 failures on existing tests
  - [ ] `pest.php` groups unit/integration/security directories
  - [ ] CI workflow runs on push and PR
- **Dependencies**: none

---

### Issue #11: ci(actions): GitHub Actions CI workflow
- **Priority**: high
- **Labels**: [ci, infrastructure]
- **Branch**: `ci/11-github-actions`
- **Evidence**: no CI workflow exists
- **Acceptance criteria**:
  - [ ] Workflow file at `.github/workflows/ci.yml`
  - [ ] `actions/checkout` pinned to full SHA `11bd71901bbe5b1630ceea73d27597364c9af683`
  - [ ] PHP 8.4, Pest with coverage min 80%, PHPStan
  - [ ] Passes on clean checkout
- **Dependencies**: #10

---

### Issue #12: refactor(seam): introduce Cacti global isolation seam
- **Priority**: medium
- **Labels**: [refactor, testability]
- **Branch**: `refactor/12-cacti-isolation-seam`
- **Evidence**: all PHP files call global Cacti functions directly — untestable without full Cacti bootstrap
- **Acceptance criteria**:
  - [ ] `src/Infrastructure/CactiDatabase.php` interface wrapping `db_execute_prepared`, `db_fetch_assoc_prepared`, etc.
  - [ ] `tests/Helpers/CactiStubs.php` provides test doubles
  - [ ] At least one production class uses the interface rather than calling globals directly
- **Dependencies**: #10

---

### Issue #13: docs(security): add SECURITY.md with vulnerability disclosure process
- **Priority**: medium
- **Labels**: [docs, security]
- **Branch**: `docs/13-security-md`
- **Evidence**: no SECURITY.md exists
- **Acceptance criteria**:
  - [ ] SECURITY.md documents the Cacti Group private disclosure process
  - [ ] References GitHub Security Advisories
  - [ ] Lists supported versions
- **Dependencies**: none
