# Intended findings (answer key)

## Dependency scanning

| Direct package | Pinned version | Expected advisories |
| --- | --- | --- |
| Newtonsoft.Json | 12.0.3 | [CVE-2024-21907: denial of service](https://github.com/advisories/GHSA-5crp-9r3c-p9vr) |
| System.Linq.Dynamic.Core | 1.2.25 | [CVE-2023-32571: code execution](https://github.com/advisories/GHSA-w65q-jcmv-28gj), [CVE-2024-51417](https://github.com/advisories/GHSA-4cv2-4hjh-77rx) |

Microsoft.Data.Sqlite supplies the real SQL database for injection exercises. Exact advisory counts depend on the feed, including newly discovered or transitive issues. Package CVEs and unsafe application configuration are separate findings.

## Application flaws

| Route | Intended weakness | Safe local probe |
| --- | --- | --- |
| POST /api/login | Concatenated SQL, plaintext stored passwords | Username `admin' --`, arbitrary password |
| GET /api/diagnostics?host=... | Shell command injection | `localhost; printf LAB_COMMAND_MARKER` |
| POST /api/import | Newtonsoft TypeNameHandling.All on untrusted JSON, no binder | `{"$type":"System.Version, System.Private.CoreLib","Major":1,"Minor":2}` |
| GET /api/users/filter?expression=... | Untrusted Dynamic LINQ expression | `Role == "admin"` |
| POST /api/crypto/encrypt | Static AES key, ECB, no authentication | Encrypt the same text twice; ciphertext repeats |
| POST /api/crypto/hash | Unsalted MD5 | Hash a password |
| GET /api/reset-token | Small token space and noncryptographic PRNG | Inspect token generation |
| GET /api/files?name=... | Path traversal | `../../appsettings.json` |
| GET /hello?name=... | Reflected XSS | `<b>unescaped</b>` demonstrates HTML interpretation |
| GET /api/fetch?url=... | SSRF | Fetch `http://127.0.0.1:5080/` |
| GET /api/invoices/2 | IDOR / missing authentication and ownership checks | Reads Bob's invoice anonymously |
| GET /redirect?url=... | Open redirect | `https://example.invalid/` |
| POST /api/xml | XXE | DTD entity referencing a local fixture file |

Unsafe deserialization reaches CLR type selection and object construction. Code execution depends on available gadget types and the runtime; a generic RCE payload is not guaranteed. The sample verifies type control without executing a gadget.

## Secret scanning fixtures

`scan-target/App/appsettings.json` contains a database password in a connection string, a weak JWT signing secret, and a payment test-key-shaped value. `scan-target/App/Fixtures/integration.env` contains AWS, GitHub, Slack, and SMTP shaped fixtures. Every value is invented and never issued; these are not working service credentials. Provider validators may reject them and some scanners suppress test/example values.

Ambiguous negative controls: the telemetry client ID, public widget key, analytics ID, build fingerprint, and `your-api-key-here` placeholder. High entropy alone does not make them credentials. Keep this guide separate from blind scanner evaluation if you do not want to reveal the labels.
