# Authentication and startup notes

This server does not implement sign-in or sessions yet. It must not assume that
all clients on a LAN are one authenticated person. The upstream personal
edition is explicitly a one-person, unreachable installation with no sign-in;
that mode does not satisfy the requested multi-device LAN deployment.

At the audited upstream revision, the browser reads deployment capabilities
at `GET /api/v2/organizations/default/deployment` before sign-in (see
`app/src/lib/deployment/queries.ts` and `api/openapi/admin-settings.yaml`).
For the team edition it reads `GET /api/v2/people/me/organizations`; a 401 is
interpreted as signed out. After the active organization is known it reads
`GET /api/v2/organizations/{organizationId}/people/me`. Do not create fake
organization or person responses to let the page through its route gate.

`app/src/routes/sign.tsx` only offers the configured Google, Microsoft and
Okta social providers and an SSO email-domain flow through Better Auth. It has
no password field. A local first-admin account therefore needs both a real,
persistent, secure server-side authentication/session implementation and a
corresponding browser sign-in/bootstrap flow; adding an endpoint alone will not
make the unmodified UI usable. Another valid approach is a configured external
identity provider with correctly implemented OAuth/SSO, but it has external
setup requirements. Implement the user's desired local, self-contained workflow
as a deliberate UI extension and keep the upstream protocol where applicable.

When implementing sessions, design an expiring one-use initial setup secret,
password hashing with a modern password KDF, random session tokens stored as
hashes, session revocation, HttpOnly and SameSite cookies, CSRF and WebSocket
origin checks, access throttling, org membership checks on every route, and
HTTPS handling. Verify entropy and password hashing support on PS5. On plain
HTTP in the LAN, credentials and cookies travel without transport encryption;
provide a practical HTTPS deployment and avoid describing HTTP as secure.
The public deployment endpoint may answer `default` to unsigned visitors;
once signed-in sessions exist it must check membership for the named org as
described in the upstream specification. The existing endpoint currently only
answers for `default` and advertises no authentication providers or other
unimplemented features.

## Local account implementation direction

The local form in `app/src/components/auth/local-sign-in.tsx` is intentionally unwired. Build a real backend and capability-gated UI together before exposing it. Use an expiring one-time setup secret delivered through a protected local operator channel, and create the first owner, organization, membership and consume the setup secret in one transaction. Store Argon2id password hashes and only hashes of cryptographically random session verifiers; require proven secure entropy on PS5. Bound hashing concurrency and measure its memory cost with PS5LM. Provide login, logout, server-side expiration and revocation, generic login errors, throttling, input limits and CSRF/Origin checks, and enforce organization membership on every protected route and socket. Never log secrets. Cookies need HttpOnly and SameSite, and Secure when HTTPS is used. Plain HTTP on the LAN does not encrypt passwords or sessions; HTTPS needs explicit deployment support.

Implement real `/api/v2/people/me/organizations` and organization-scoped `people/me` from persistent membership and sessions, matching their OpenAPI schemas. The existing OAuth/SSO sign-in screen needs a local form integration; upstream `authProviders` does not declare local passwords. Verify concurrent bootstrap, token reuse/expiry, throttling, session fixation, CSRF, origin, revocation, cross-organization access, restarts and browser journeys before marking authentication complete.
