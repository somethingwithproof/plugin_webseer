# plugin_webseer — Security Audit

Audit date: 2026-03-09
Auditor: principal-level static review + manual code inspection
Scope: all PHP files in plugin root, includes/, classes/

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High     | 4 |
| Medium   | 3 |
| Low      | 2 |
| **Total**| **11** |

The most urgent issues are the unguarded SSRF vector (any authenticated admin
can point the poller at internal infrastructure) and the SQL injection in
`plugin_webseer_update_contacts()` which concatenates `email_address` from
`user_auth` directly into a `db_execute()` call.

---

## All Findings

### FIND-001
- **Category**: SQL Injection
- **Severity**: Critical
- **Confidence**: High
- **File**: `includes/functions.php`
- **Lines**: 319–325
- **Evidence**:
  ```php
  $cid = db_fetch_cell('SELECT id FROM plugin_webseer_contacts WHERE type="email" AND user_id=' . $u['id']);
  if ($cid) {
      db_execute("REPLACE INTO plugin_webseer_contacts (id, user_id, type, data) VALUES ($cid, " . $u['id'] . ", 'email', '" . $u['email_address'] . "')");
  } else {
      db_execute("REPLACE INTO plugin_webseer_contacts (user_id, type, data) VALUES (" . $u['id'] . ", 'email', '" . $u['email_address'] . "')");
  }
  ```
- **Description**: `email_address` from `user_auth` is concatenated directly
  into `db_execute()` without parameterisation. A user whose email contains a
  single quote (e.g. `foo',(SELECT password FROM user_auth LIMIT 1),'x`) can
  corrupt or exfiltrate data. The value is entirely user-controlled via the
  Cacti user profile page.
- **Exploitability**: Post-authentication; any user who can edit their own email
  address. In Cacti's default configuration that includes non-admin users.
- **Remediation**: Replace both `db_execute()` calls with
  `db_execute_prepared()` using `?` placeholders for `$cid`, `$u['id']`, and
  `$u['email_address']`.
- **TDD Status**: Ready — seam is Cacti's `db_execute_prepared()` stub.

---

### FIND-002
- **Category**: SSRF (Server-Side Request Forgery)
- **Severity**: Critical
- **Confidence**: High
- **File**: `classes/cURL.php`
- **Lines**: 86–123 (`post()`), 129–280 (`get()`)
- **Evidence**:
  ```php
  $process = curl_init($url);
  // ...
  $process = curl_init($url);
  ```
- **Description**: The `cURL` class accepts any URL from `plugin_webseer_urls.url`
  and fetches it without validating the host against private/internal IP ranges.
  An authenticated admin can create a service check targeting
  `http://169.254.169.254/latest/meta-data/` (AWS IMDS), internal APIs, or
  other private services. Results are stored in `plugin_webseer_urls_log` and
  displayed in the history view, making this a full read-SSRF.
- **Exploitability**: Post-authentication (admin role). In multi-tenant Cacti
  deployments, any realm that can manage service checks is sufficient.
- **Remediation**: Validate the target URL through `UrlValidator::isAllowed()`
  before calling `curl_init()`. Block RFC-1918, loopback, link-local, and
  non-http(s) schemes. See `src/Security/UrlValidator.php`.
- **TDD Status**: Seam required — `UrlValidator` class is in place; wire into
  `cURL::get()` and `cURL::post()`.

---

### FIND-003
- **Category**: Unsafe Deserialization
- **Severity**: High
- **Confidence**: High
- **File**: `includes/functions.php`
- **Lines**: 75, 107
- **Evidence**:
  ```php
  $servers = unserialize(base64_decode($servers));
  // ...
  $urls = unserialize(base64_decode($urls));
  ```
- **Description**: Data returned from a remote webseer server over HTTP is
  base64-decoded and then passed to `unserialize()` without
  `['allowed_classes' => false]`. If the remote server is compromised or the
  connection is intercepted (no TLS verification in `cURL::post()`), an
  attacker can achieve remote code execution via PHP object injection.
- **Exploitability**: Requires MITM or compromise of one webseer slave server.
  Realistic in internal network environments where TLS is not enforced.
- **Remediation**: Pass `['allowed_classes' => false]` as second argument to
  both `unserialize()` calls. Better: switch the inter-server protocol to JSON.
- **TDD Status**: Ready — stub `unserialize()` contract is documented in
  `tests/Security/SsrfTest.php`.

---

### FIND-004
- **Category**: SQL Injection (filter bypass)
- **Severity**: High
- **Confidence**: High
- **File**: `webseer.php`
- **Lines**: 744–749
- **Evidence**:
  ```php
  $sql_where .= ($sql_where == '' ? 'WHERE ' : ' AND ') .
      'display_name RLIKE \'' . get_request_var('rfilter') . '\' OR ' .
      'url RLIKE \'' . get_request_var('rfilter') . '\' OR ' .
      'search RLIKE \'' . get_request_var('rfilter') . '\' OR ' .
      'search_maint RLIKE \'' . get_request_var('rfilter') . '\' OR ' .
      'search_failed RLIKE \'' . get_request_var('rfilter') . '\'';
  ```
- **Description**: `rfilter` is validated as a regex via
  `FILTER_VALIDATE_IS_REGEX` in `webseer_request_validation()` (line 473), but
  the validated value is still concatenated into a raw SQL RLIKE clause. A
  regex that is also a SQL fragment (e.g. `' OR '1'='1`) can escape the RLIKE
  context and alter query semantics.
- **Exploitability**: Post-authentication. The regex validator reduces the
  attack surface but does not eliminate it because the validated value is not
  then parameterised.
- **Remediation**: Use `db_fetch_assoc_prepared()` with `? RLIKE ?` binding for
  each column, or apply `db_qstr()` to `rfilter` before concatenation.
- **TDD Status**: Ready.

---

### FIND-005
- **Category**: SQL Injection
- **Severity**: High
- **Confidence**: High
- **File**: `webseer_proxies.php`
- **Lines**: 255
- **Evidence**:
  ```php
  $sql_where .= ($sql_where == '' ? 'WHERE ' : ' AND ') .
      ' name LIKE "%' . get_request_var('filter') . '%" OR hostname LIKE "%' .
      get_request_var('filter') . '%"';
  ```
- **Description**: `filter` is taken from `get_request_var()` (no explicit
  integer or regex validation shown for this field in `request_validation()`)
  and concatenated directly into a LIKE clause. Single quotes, percent signs,
  and backslashes are not escaped. This allows SQLi via the proxy search box.
- **Exploitability**: Post-authentication.
- **Remediation**: Replace with a prepared statement:
  `WHERE name LIKE ? OR hostname LIKE ?` with `'%' . $filter . '%'` as bound
  parameters. Alternatively wrap with `db_qstr()`.
- **TDD Status**: Ready.

---

### FIND-006
- **Category**: SQL Injection
- **Severity**: High
- **Confidence**: Medium
- **File**: `remote.php`
- **Lines**: 174–176
- **Evidence**:
  ```php
  $ip = str_replace(array("'", '\\'), '', $_POST['ip']);
  $row = db_fetch_row("SELECT * FROM plugin_webseer_servers WHERE ip = '$ip'");
  ```
- **Description**: The SETMASTER handler sanitises `$_POST['ip']` by stripping
  single quotes and backslashes, then interpolates it directly into
  `db_fetch_row()`. This manual sanitisation does not cover all SQL injection
  vectors (e.g. MySQL comment syntax `/**/`, numeric injection). The correct
  fix is parameterisation, not character stripping.
- **Exploitability**: The handler is only reached when `$remoteip` matches a
  known server in `plugin_webseer_servers` (line 46), limiting exposure to
  requests originating from registered slave servers.
- **Remediation**: Replace with
  `db_fetch_row_prepared('SELECT * FROM plugin_webseer_servers WHERE ip = ?', [$ip])`
  and remove the manual strip.
- **TDD Status**: Ready.

---

### FIND-007
- **Category**: XSS (Stored)
- **Severity**: Medium
- **Confidence**: High
- **File**: `webseer_servers.php`
- **Lines**: 434
- **Evidence**:
  ```php
  form_selectable_cell("<a class='linkEditMain' href='" . $row['url'] . "' target=_new><b>" . $row['url'] . '</b></a>', $row['id']);
  ```
- **Description**: `$row['url']` from `plugin_webseer_servers_log` is
  interpolated into an anchor `href` and anchor text without `html_escape()`.
  A URL containing `javascript:alert(1)` or a double-quote breaking out of the
  href attribute would execute arbitrary JavaScript when an admin views server
  history.
- **Exploitability**: Post-authentication. URL value is admin-entered, but a
  compromised slave server could inject it via the HOSTDOWN/ADDSERVER remote
  actions.
- **Remediation**: Wrap both occurrences of `$row['url']` with `html_escape()`.
  Additionally validate that the scheme is `http` or `https` before rendering
  as a link.
- **TDD Status**: Ready.

---

### FIND-008
- **Category**: XSS (Stored)
- **Severity**: Medium
- **Confidence**: High
- **File**: `webseer.php`
- **Lines**: 651
- **Evidence**:
  ```php
  form_selectable_cell("<a class='linkEditMain' href='" . $row['url'] . "' target=_new>" . $row['url'] . '</a>', $row['id']);
  ```
- **Description**: Same pattern as FIND-007 in the URL check history view.
  `$row['url']` from `plugin_webseer_urls_log` is not escaped in either the
  href or the link text.
- **Exploitability**: Same as FIND-007.
- **Remediation**: Wrap with `html_escape()` in both positions.
- **TDD Status**: Ready.

---

### FIND-009
- **Category**: Missing TLS verification
- **Severity**: Medium
- **Confidence**: High
- **File**: `classes/cURL.php`
- **Lines**: 192–198
- **Evidence**:
  ```php
  if ($this->host['checkcert'] == '') {
      $cert_opts = array(
          CURLOPT_SSL_VERIFYPEER => FALSE,
          CURLOPT_SSL_VERIFYHOST => FALSE,
      );
  }
  ```
- **Description**: When `checkcert` is empty (the default for new service
  checks), TLS certificate validation is disabled. Combined with FIND-003
  (unsafe unserialize) this means inter-server communication happens over
  unverified TLS, enabling MITM attacks that could deliver malicious
  serialised payloads.
- **Exploitability**: Network-adjacent attacker who can intercept traffic
  between webseer nodes.
- **Remediation**: Flip the default: enable `CURLOPT_SSL_VERIFYPEER` and
  `CURLOPT_SSL_VERIFYHOST` by default; only disable when `checkcert` is
  explicitly set to a bypass flag. The bundled `ca-bundle.crt` should be
  used via `CURLOPT_CAINFO`.
- **TDD Status**: Ready.

---

### FIND-010
- **Category**: Information Disclosure
- **Severity**: Low
- **Confidence**: Medium
- **File**: `remote.php`
- **Lines**: 183–191
- **Evidence**:
  ```php
  case 'GETSERVERS':
      print 'SERVERS=' . base64_encode(serialize($servers));
      break;
  case 'GETURLS':
      $urls = db_fetch_assoc('SELECT * FROM plugin_webseer_urls');
      // ...
      print 'URLS=' . base64_encode(serialize($urls));
  ```
- **Description**: `remote.php` is loaded via `cli_check.php` which blocks web
  access (defines `CACTI_CLI_ONLY`). However `remote.php` begins with
  `chdir('../../'); require_once('./include/cli_check.php')` — if this file
  is web-accessible in some installations it would expose all server and URL
  data to any IP that is already registered in `plugin_webseer_servers`.
- **Exploitability**: Low — gated behind IP check on line 46. Risk is higher
  if `cli_check.php` does not reliably block HTTP access in all deployment
  configurations.
- **Remediation**: Confirm `cli_check.php` blocks web access, or add an
  explicit `CACTI_CLI_ONLY` guard at the top of `remote.php`.
- **TDD Status**: Seam required — needs integration test with a mock HTTP
  context.

---

### FIND-011
- **Category**: Missing auth check on remote.php actions
- **Severity**: Low
- **Confidence**: Medium
- **File**: `remote.php`
- **Lines**: 41–194
- **Evidence**:
  ```php
  $servers = db_fetch_assoc('SELECT * FROM plugin_webseer_servers');
  foreach ($servers as $server) {
      if ($server['ip'] == $remoteip) {
          $action = get_nfilter_request_var('action', '');
          switch ($action) { ... }
  ```
- **Description**: The only authentication is an IP address match against the
  `plugin_webseer_servers` table. There is no token, HMAC, or session check.
  An attacker who can spoof their source IP (e.g. from within the same /24) or
  who can register their IP as a server can perform all remote actions including
  TRUNCATE-equivalent operations (DELETEURL/DELETESERVER).
- **Exploitability**: Requires either IP spoofing or adding a rogue server
  record to the database — both post-compromise scenarios.
- **Remediation**: Add a shared-secret HMAC header verified on each request, or
  move to mutual TLS between webseer nodes.
- **TDD Status**: Seam required.

---

## Unknowns

- `webseer_process.php` was not present in the repository at audit time.
  It is launched via `exec_background()` in `poller_webseer.php` and handles
  the actual HTTP checks. Any security issues in that file are out of scope for
  this audit.
- The `mxlookup` class was not fully reviewed. DNS lookup results in
  `plugin_webseer_check_dns()` are stored in `$results['data']` and may be
  displayed; verify escaping at render time.

## Blind Spots

- Dynamic SQL via `get_order_string()` — this Cacti core function sanitises
  `sort_column` and `sort_direction` but its implementation was not inspected.
  If it does not validate against a column allowlist the ORDER BY clauses in
  `list_urls()`, `list_servers()`, and history views are injection points.
- The `sanitize_unserialize_selected_items()` Cacti core function is used
  throughout. Its implementation was not audited here.

## Seams Needed Before Full TDD

1. Extract `UrlValidator::isInternalHost()` and wire it into `cURL::get()` —
   skeleton is at `src/Security/UrlValidator.php`.
2. Extract the `db_execute()` call sites in `plugin_webseer_update_contacts()`
   into a `ContactRepository` class that accepts `db_execute_prepared` as a
   collaborator.
3. Replace `unserialize()` in `plugin_webseer_refresh_servers()` and
   `plugin_webseer_refresh_urls()` with JSON decode, then the seam is trivial.

## Estimated Effort

| Work item | Estimate |
|-----------|----------|
| FIND-001 SQL injection fix | 30 min |
| FIND-002 SSRF guard (wire UrlValidator) | 2 h |
| FIND-003 unsafe unserialize | 1 h |
| FIND-004 rfilter parameterisation | 30 min |
| FIND-005 proxy filter parameterisation | 30 min |
| FIND-006 SETMASTER parameterisation | 15 min |
| FIND-007/008 XSS in URL cells | 30 min |
| FIND-009 TLS default flip | 30 min |
| FIND-010/011 remote.php hardening | 3 h |
| Test harness bootstrap (Pest 4) | 1 h |
| **Total** | **~10 h** |
