# Intentional flaw baseline

This is the answer key for the application as authored, for comparing Veracode, Snyk, and other tools. Locations are relative to the repository root; line numbers refer to the current source. IDs remain useful if line numbers move. CWE mappings are suggested normalization categories, not required vendor rule names.

Exclude this file and `docs/FINDINGS.md` from scanner input to avoid leaking the answer key. README.md, requests.http, and scripts/smoke.py also describe or exercise cases. The scan target has neutral project and landing-page names; fixture label comments have been removed. This document inventories intentional cases; it does not claim that a security scan found no additional issues.

## Validation and scoring

The baseline comes from source inspection. NuGet restore was denied by this environment, so the app has not been compiled or exercised here. Sample inputs are intended probes, not recorded successful exploit results. Unsafe deserialization and dependency RCE advisories do not establish a working RCE exploit on this runtime.

Compare SAST, SCA, and secret scanning separately. Record tool version, scan date, rules, exclusions, restore success, and whether source or compiled artifacts were scanned. Mark unsupported categories as not evaluated. Match findings by root cause and location rather than requiring exact titles, severities, CWE labels, or raw counts. A tool can legitimately group overlapping cases or report both a package advisory and a source-level misuse.

Core source cases: APP-01 through APP-16. APP-17 and APP-18 are supporting design weaknesses with limited standalone impact in this app. CFG-01 is an inactive configuration fixture. Secret positives mean credential-shaped content, never verified live credentials. Negative controls are listed separately.

## Application findings

All locations in this section refer to `scan-target/App/Program.cs`.

| ID | Intended finding | Location | Input to sensitive operation / why it matters | Suggested CWE |
| --- | --- | --- | --- | --- |
| APP-01 | SQL injection | Line 40, POST `/api/login` | Both `Username` and `Password` are interpolated into SQL executed by `ExecuteReader`. SQL syntax can change the authentication query. Treat the two parameters as one root cause unless scoring input paths separately. | 89 |
| APP-02 | OS command injection | Lines 49–52, GET `/api/diagnostics` | Query `host` is concatenated into `/bin/sh -c` input. Shell operators are interpreted, allowing commands with the app process's privileges. Using `ArgumentList` does not help when an argument is shell program text. | 78 |
| APP-03 | Unsafe deserialization | Line 62, POST `/api/import` | The entire request body reaches `JsonConvert.DeserializeObject` with `TypeNameHandling.All` and no restrictive binder. JSON can select CLR types and trigger their construction. RCE requires available gadget types and is not established here. | 502 |
| APP-04 | Dynamic expression injection | Line 69, GET `/api/users/filter` | Query `expression` reaches Dynamic LINQ `Where` without a constrained grammar or allowlist. The deliberately old parser has security advisories. This is an expression sink, separate from SQL injection; filtering the in-memory array does not execute SQL. | 943; some tools may use 94 |
| APP-05 | Hardcoded encryption key | Line 75, POST `/api/crypto/encrypt` | The AES key is a fixed source literal. Anyone with the source can recover the key. This is also SECRET-09; do not count two independent root causes. | 321 |
| APP-06 | Insecure block cipher mode | Line 76, POST `/api/crypto/encrypt` | AES uses ECB. Equal plaintext blocks under the same key produce equal ciphertext blocks, revealing patterns. AES itself and the 256-bit key length are not the flaw. | 327 |
| APP-07 | Encryption without integrity protection | Lines 74–80, POST `/api/crypto/encrypt` | Raw AES ciphertext has no authentication tag or MAC. It lacks tamper detection. There is no decrypt/consume endpoint here, so a downstream tampering attack is not demonstrated. Tools may group this with APP-06. | 353; sometimes 327 |
| APP-08 | Weak hash algorithm | Line 83, POST `/api/crypto/hash` | Caller text is hashed with MD5, unsuitable for collision-resistant security uses. The endpoint accepts generic text: it does not store password hashes. Do not describe it as an implemented MD5 password database. | 328 |
| APP-09 | Noncryptographic token generation | Line 84, GET `/api/reset-token` | A token-like value uses `System.Random`, not a cryptographic generator. There is no reset-token redemption flow, so an account takeover claim would exceed the evidence. | 338 |
| APP-10 | Small token search space | Line 84, GET `/api/reset-token` | `Next(100000, 999999)` offers 899,999 possible values, about 19.8 bits. Related to APP-09 but distinct from the PRNG choice. No redemption flow exists to test brute force against. | 330 |
| APP-11 | Path traversal / arbitrary file read | Line 86, GET `/api/files` | Query `name` is joined to a base directory and passed to `File.ReadAllText` without canonicalization and containment enforcement. `..` or rooted input can escape the intended directory subject to process permissions. | 22 |
| APP-12 | Reflected cross-site scripting | Line 87, GET `/hello` | Query `name` is inserted into an HTML response without HTML encoding. Browser markup and script can be supplied. | 79 |
| APP-13 | Server-side request forgery | Lines 88–91, GET `/api/fetch` | Query `url` reaches `HttpClient.GetStringAsync` without destination checks. Requests can target services reachable from the app, including loopback. Default redirect following expands destination control. | 918 |
| APP-14 | Missing object authorization / IDOR | Lines 93–101, GET `/api/invoices/{id}` | The caller chooses an invoice ID and receives owner, amount, and account data without identity or ownership checks. The SQL is parameterized; SQL injection on this route is not an intended finding. | 862 / 639 |
| APP-15 | Open redirect | Line 103, GET `/redirect` | Query `url` is passed to `Results.Redirect` without restricting external destinations. | 601 |
| APP-16 | XML external entity processing | Lines 104–111, POST `/api/xml` | Untrusted XML is parsed with DTD processing enabled and external resolvers configured on both reader and document. External entities can read files or initiate requests; resolved text is returned. Treat both resolver settings as one parsing flow. | 611 |
| APP-17 | Plaintext password storage | Lines 22–23 and 40 | Seed passwords are persisted as plaintext SQLite fields and compared directly in the login query. There is no salted, adaptive password hashing. | 256 |
| APP-18 | Hardcoded local account credentials | Line 23 | Alice and administrator passwords are literal seed values. Anyone with source knows them. Login only returns a record and creates no session, so do not claim these credentials establish a privileged session. Also SECRET-10 and SECRET-11. | 798 |

### Local probe examples

Run only against this local lab. URL-encode query values where needed; `requests.http` includes examples.

| Case | Probe | Intended observation |
| --- | --- | --- |
| APP-01 | POST `/api/login` with `{"username":"admin' --","password":"wrong"}` | Administrator record returned despite incorrect password. |
| APP-02 | `host=localhost; printf LAB_COMMAND_MARKER` | Output includes the marker from the injected second command. |
| APP-03 | POST `/api/import` with `{"$type":"System.Version, System.Private.CoreLib","Major":1,"Minor":2}` | A `System.Version` instance demonstrates attacker-selected type construction, not RCE. |
| APP-04 | `expression=Role == "admin"` | Demonstrates that caller-supplied expression syntax is evaluated; this benign probe does not prove code execution. |
| APP-06 | Encrypt text containing repeated 16-byte blocks | Equal plaintext blocks produce equal ciphertext blocks. Repeating a whole request also produces the same ciphertext because the key is fixed. |
| APP-08 | POST `/api/crypto/hash` with `{"text":"password"}` | MD5 result `5F4DCC3B5AA765D61D8327DEB882CF99`. |
| APP-11 | `name=../../appsettings.json` | Reads configuration above the intended files directory. |
| APP-12 | `name=<b>marker</b>` | HTML is emitted unescaped. This proves HTML injection; browser script execution is a further XSS check. |
| APP-13 | `url=http://127.0.0.1:5080/` | Server fetches its own loopback listener. |
| APP-14 | GET `/api/invoices/2` without authentication | Bob's invoice and account field are returned. |
| APP-15 | `url=https://example.invalid/` | Response has an external redirect Location. Inspect the response without following it. |
| APP-16 | XML with a DTD entity referencing `file:///etc/hostname`, as in requests.http | Linux host name is returned via entity expansion. |

## Dependency findings (SCA)

Location: `scan-target/App/App.csproj`. Two direct packages deliberately carry three known advisory cases. These identifiers are the intended starting baseline, not a guarantee that a current feed reports exactly three findings.

| ID | Package / version / line | Advisory | Expected issue |
| --- | --- | --- | --- |
| SCA-01 | Newtonsoft.Json 12.0.3, line 9 | [CVE-2024-21907 / GHSA-5crp-9r3c-p9vr](https://github.com/advisories/GHSA-5crp-9r3c-p9vr) | Denial of service involving deeply nested JSON. Advisory affects versions before 13.0.1. Request JSON reaches this package at `/api/import`; no resource-exhaustion test was run. |
| SCA-02 | System.Linq.Dynamic.Core 1.2.25, line 10 | [CVE-2023-32571 / GHSA-w65q-jcmv-28gj](https://github.com/advisories/GHSA-w65q-jcmv-28gj) | Arbitrary code/command execution through untrusted parsed expressions. Affected range is >= 1.0.7.10 and < 1.3.0. `/api/users/filter` exposes an untrusted expression sink. |
| SCA-03 | System.Linq.Dynamic.Core 1.2.25, line 10 | [CVE-2024-51417 / GHSA-4cv2-4hjh-77rx](https://github.com/advisories/GHSA-4cv2-4hjh-77rx) | Access to properties on reflection types and static properties/fields. Advisory affects versions before 1.6.0. |

`Microsoft.Data.Sqlite` 10.0.0 is the SQL exercise dependency, not an intentionally selected vulnerable package. Newly reported advisories or vulnerable transitive dependencies should be reviewed as additional findings rather than automatically scored as false positives. Package-presence SCA and reachable/exploitable SCA are different results. A packages.lock.json file is present in the scan target. The initial build attempt was blocked by NuGet access; runtime verification has not been completed by this agent.

## Credential and secret fixtures

All credentials were invented for this lab. None were issued by a provider or verified live. Score these as static credential/secret exposure fixtures; a tool that validates and rejects them as inactive is behaving differently from a pattern-only scanner, not necessarily missing a real credential.

| ID | Location | Fixture | Expected interpretation |
| --- | --- | --- | --- |
| SECRET-01 | `scan-target/App/appsettings.json:4` | Password in `ConnectionStrings.LegacyReporting` | Hardcoded database password in connection string (CWE-798). Inactive configuration; no connection to this server is made. |
| SECRET-02 | `scan-target/App/appsettings.json:6` | `Jwt.SigningKey` | Literal JWT signing-secret fixture (CWE-798 / 321). No JWT signing or validation exists, so do not claim working token forgery. |
| SECRET-03 | `scan-target/App/appsettings.json:7` | `Payments.ApiKey` | Invented payment test-key-shaped value. Pattern detection is optional depending on provider format checks and test-key suppression. |
| SECRET-04 | `scan-target/App/Fixtures/integration.env:2` | `AWS_ACCESS_KEY_ID` | Invented AWS access-key identifier. Typically grouped with SECRET-05; an identifier alone is not a secret authenticator. |
| SECRET-05 | `scan-target/App/Fixtures/integration.env:3` | `AWS_SECRET_ACCESS_KEY` | Invented AWS secret-key-shaped value. Context-aware detection can use the neighboring access-key ID. |
| SECRET-06 | `scan-target/App/Fixtures/integration.env:4` | `GITHUB_TOKEN` | Invented `ghp_` token-shaped value. Provider-specific validation can reject it. |
| SECRET-07 | `scan-target/App/Fixtures/integration.env:5` | `SLACK_BOT_TOKEN` | Invented `xoxb-` bot-token-shaped value with obvious zero/test components. Provider and example-value filters can suppress it. |
| SECRET-08 | `scan-target/App/Fixtures/integration.env:6` | `SMTP_PASSWORD` | Literal SMTP password fixture; generic password/context rule rather than provider token format. |
| SECRET-09 | `scan-target/App/Program.cs:75` | AES key literal | Actual local encryption key used by the endpoint. Same root cause as APP-05. |
| SECRET-10 | `scan-target/App/Program.cs:23` | Alice seed password | Hardcoded password used by the local login query. Same source root cause as APP-18. |
| SECRET-11 | `scan-target/App/Program.cs:23` | Administrator seed password | Second local password literal; tools may group both literals on this line. Same source root cause as APP-18. |

The `.env` extension is deliberately not excluded by `.gitignore`. Ensure the scanner includes it. No private key file, working cloud token, OAuth client secret, or real production credential was added.

### Ambiguous and negative secret controls

These are intentionally nonsecret values. A tool may report informational candidates, but reporting them as confirmed working credentials is unsupported.

| ID | Location | Value category | Baseline classification |
| --- | --- | --- | --- |
| NEG-01 | `scan-target/App/appsettings.json:8`, `Telemetry.ClientId` | Hexadecimal client identifier | Public identifier; not an authentication secret. |
| NEG-02 | `scan-target/App/appsettings.json:8`, `Telemetry.PublicWidgetKey` | Public widget key | Public configuration value. |
| NEG-03 | `scan-target/App/Fixtures/integration.env:8`, `ANALYTICS_ID` | High-entropy-looking hexadecimal ID | Identifier; entropy alone does not establish a secret. |
| NEG-04 | `scan-target/App/Fixtures/integration.env:9`, `EXAMPLE_API_TOKEN` | `your-api-key-here` | Placeholder, not a credential. |
| NEG-05 | `scan-target/App/Fixtures/integration.env:10`, `BUILD_FINGERPRINT` | Hexadecimal build fingerprint | Nonsecret fingerprint. |

The `DEMO-ACCOUNT-*` invoice values are also synthetic records, not financial credentials. Host names ending in `.invalid` are deliberate nonresolving fixture destinations.

## Inactive configuration weakness

| ID | Location | Intended issue | Scope and scoring |
| --- | --- | --- | --- |
| CFG-01 | `scan-target/App/appsettings.json:4` | `TrustServerCertificate=True` bypasses server certificate validation for a client connection using this connection string (CWE-295). | Configuration-pattern finding only. The application uses SQLite and never opens `LegacyReporting`; no active TLS-bypass path is implemented. |

## Overlap and claims to avoid

- APP-01's login bypass is an impact of SQL injection; it need not be a second independent authentication finding.
- APP-14 includes both anonymous access and missing ownership enforcement on the same invoice flow. Grouping is reasonable. The rest of the app also has no authentication middleware, but each public route should not become a separate missing-authentication score item without a defined protection requirement.
- APP-05 / SECRET-09 and APP-18 / SECRET-10 / SECRET-11 overlap across categories. Keep category scores separate or deduplicate in an aggregate score.
- APP-03 is application deserialization configuration; SCA-01 is a package denial-of-service advisory. They are distinct. APP-04 and SCA-02 / SCA-03 overlap in affected parser use but measure source misuse versus package advisories.
- MD5 has no salt in this implementation, but there is no MD5 password-storage path. APP-17 is the actual password-storage flaw.
- ECB does not use an IV. Do not invent a separate hardcoded-IV finding. No DES, RSA misuse, or BinaryFormatter case exists.
- Absence of HTTPS on the intentional loopback listener, production security headers, rate limiting, request-body limits, and a token lifecycle are not separately authored benchmark cases. A tool may raise contextual hardening concerns; review their evidence separately.
- Parser/resource exhaustion beyond SCA-01, process hangs, verbose error disclosure, CSRF, SQL injection in invoice lookup, and JWT algorithm confusion were not independently implemented as ground-truth cases.

## Comparison worksheet

Copy a row per case and tool. For cross-category overlap, reference the shared case instead of inflating the total.

| Tool / version | Case ID | Status | Reported location / rule | Notes |
| --- | --- | --- | --- | --- |
| | | Detected / Missed / Not evaluated / Additional finding | | |

Use the five NEG cases to evaluate false-positive behavior. Do not calculate a single precision percentage from this small inventory unless additional reported findings have been independently reviewed: findings outside the intentional list can still be valid.
