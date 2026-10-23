# SafeVault security capstone

ASP.NET Core 10 course demonstration with Identity, signed JWT authentication, server-validated RBAC, owner-scoped SQLite records, parameterized EF Core queries and encoded HTML previews.

## Reproduce

Requires the .NET 10 SDK. From this directory:

```powershell
dotnet test SafeVault.Api.Tests/SafeVault.Api.Tests.csproj --logger 'trx;LogFileName=security-regression.trx' --results-directory ./TestResults
```

The tests use isolated in-memory SQLite and a clearly test-only signing key. No real account credentials are included.

For a local demonstration, set `Jwt__SigningKey` to a new random secret of at least 32 UTF-8 bytes, then run `dotnet run --project SafeVault.Api`. Configure a trusted HTTPS binding for non-test use. Register at `/api/auth/register`, authenticate at `/api/auth/login`, use the returned token as `Authorization: Bearer <token>`.

## Security controls

- Required bounded request validation, blank-content rejection and trimmed title storage.
- EF Core LINQ parameters for title search, with owner ID derived from verified `sub` rather than request data.
- Identity password hashing, password policy and five-failure/15-minute login lockout.
- HS256 JWT signature, issuer, audience, lifetime and algorithm checks, startup configuration validation.
- Server role membership is reloaded after token validation so a revoked Admin role immediately loses privilege.
- Public registration only assigns User; client-supplied role fields cannot grant Admin.
- HTML encoding at preview rendering, CSP and nosniff. Input validation is not presented as a replacement for parameters or encoding.

## Executed verification

On 2026-10-23, .NET SDK 10.0.402 executed the MSTest/WebApplicationFactory suite: **9 passed, 0 failed, 0 skipped**. See `evidence/test-summary.txt` and `evidence/security-regression.trx`.

Coverage: missing authentication, cross-user access and SQL-injection payloads, ordinary/Admin access, XSS encoding, invalid input, lockout despite correct password, invalid/tampered JWT, registration role injection, and revocation of a role on an unexpired token.

## AI assistance and debugging

The initial local draft was authored with Codex. On 2026-10-23 GitHub Copilot Chat was actually used to generate secure-code examples and review validation, parameterized queries, Identity/JWT/RBAC, SQLi/XSS defenses and regression tests. Its suggestions were reviewed and adapted, not accepted blindly. For example its first example incorrectly expected HTTP 423 for lockout; the actual API intentionally returns generic 401 and the executed test uses that contract. Its example DTO omitted IValidatableObject and its sample routes differed; these were corrected.

Copilot-assisted changes include explicit normalized-content validation, UTC-tick SQLite conversion guidance, server-side role refresh after JWT validation and additional lockout, JWT forgery, registration-role and role-revocation regressions. Transcript evidence is in `evidence/copilot-chat-visible.txt`. Copilot did not execute the tests; the local .NET test runner did.

Actual initial build/runtime faults found and repaired: ValidationProblem overload mismatch, missing TestHost namespace, early JWT configuration resolution before test-host hooks, record validation metadata on the wrong target, and unsupported SQLite DateTimeOffset ordering. The starting draft already contained parameterized queries and encoded previews; this report does not invent a successful SQL injection or XSS exploitation in that starting version. Regression payloads demonstrate the defenses remain effective.

## Demo limitations

This is not a production deployment. It uses EnsureCreated and requires reviewed migrations before existing databases are upgraded (the timestamp storage conversion changes schema expectations). Add production transport enforcement, managed keys/rotation, operational rate limiting, audit/monitoring, backup and identity lifecycle controls. The admin list is unpaginated for this small course demo. Role refresh adds an Identity database read per authenticated request. A login lockout prevents new logins but does not automatically revoke an already issued access token; access tokens expire after 15 minutes.

Public test evidence preserves outcomes and redacts local absolute paths, machine identity and runner username. The original runner artifact is retained locally.

