# SafeVault security project

SafeVault uses ASP.NET Core's `PasswordHasher<TUser>` to store password hashes, secure HTTP-only cookies for sessions, and role-based authorization for administrator routes. New public registrations are always assigned the `User` role.

## Run locally

Configure the initial administrator through environment variables or a secret manager; do not commit credentials:

```powershell
$env:SafeVault__BootstrapAdmin__Username = "AdminOne"
$env:SafeVault__BootstrapAdmin__Email = "admin@example.com"
$env:SafeVault__BootstrapAdmin__Password = "<use-a-unique-secret-of-at-least-12-characters>"
dotnet run --project SafeVault --launch-profile https
```

The bootstrap administrator is created only when the configured username is absent. If the account already exists as a standard user, startup fails instead of silently elevating it. Once created, the account can be managed through the administrator role endpoint.

Cookies are marked `Secure`, `HttpOnly`, and `SameSite=Strict`, so use HTTPS. The HTML registration form includes an antiforgery token. Existing Activity 1 SQLite databases are migrated at startup; old rows remain `User` accounts with empty password hashes and cannot log in until a password-reset flow is added.

## Endpoints

- `POST /users` — form registration (`username`, `email`, `password`); requires the token from `GET /`.
- `POST /login` — JSON credentials; issues the authentication cookie.
- `POST /logout` — ends the authenticated session.
- `GET /profile` — returns the signed-in user and role.
- `GET /admin/dashboard` — administrator only.
- `PUT /admin/users/{username}/role` — administrator-only role assignment (`User` or `Admin`).
- `GET /openapi/v1.json` — development OpenAPI document.

Role changes invalidate existing cookies for the affected user; the user must sign in again to receive their updated role.

## Security review and fixes

Copilot-assisted review found no exploitable SQL injection or XSS issue in the submitted code. Database access uses parameterized SQL, user fields are validated, and values intended for HTML output are encoded. The registration form also uses antiforgery protection, and authenticated routes enforce role checks.

The security tests include SQL-injection and script-injection payloads, password-hash verification, invalid-login checks, and user/admin access-control scenarios. Copilot assisted with implementing the defenses, generating attack-focused tests, reviewing the code, and running the test suite.

## Verify

```powershell
dotnet test SafeVault.slnx
```
