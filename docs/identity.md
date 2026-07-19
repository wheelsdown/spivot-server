# Identity & Onboarding

How a device becomes a trusted OpenCaravan participant: the server's
certificate authority, the invite tokens that gate enrollment, and the
policy controlling who may mint them.

## Certificate Authority

Spivot Server acts as its own certificate authority for the client
apps that enroll with it. The CA's keypair and self-signed root
certificate are generated on demand and persisted under
`<data-dir>/identity/`:

```bash
spivot-server ca init        # generate keypair + self-signed root if absent
spivot-server ca cert        # print the CA's certificate as PEM
```

`ca init` is idempotent: re-running it loads the existing CA and
prints its fingerprint. The key is written with 0600 permissions and
is never logged. Subject defaults to `CN=Spivot Server CA`; override
with `--common-name` and `--organization` flags (or
`SPIVOT_CA_COMMON_NAME` / `SPIVOT_CA_ORGANIZATION` env vars).

Every leaf certificate the CA signs is recorded in the
`issued_certificates` audit table (serial, subject, validity window,
issuance time, revocation time). The identity middleware resolves a
presented client certificate's serial back to its enrolled
`(user_id, client_app_id)` through that table, so revoking a row by
setting `revoked_at` is sufficient to break the identity binding —
short-lived (7-day) leaf certs make CRL/OCSP infrastructure
unnecessary for v0.

Enrollment responses carry the CA chain so apps can pin the root.
That pin is what lets enrolled apps validate each other's signed
payloads peer-to-peer, without the server in the path.

## Client App Enrollment Invites

Spivot Server uses single-use invite tokens to gate which apps may
enroll. Each token carries a scope (`server_registration` for new
users, `journey` for joining a private journey), an expiration, and a
one-time-use guarantee. Only the SHA-256 hash of the token is stored
on disk; the plaintext is shown to the operator exactly once at
issuance.

### First-run bootstrap

The first time a fresh server starts with zero registered users and no
active `server_registration` invite, it self-issues a 24-hour invite
and prints a fenced banner to its stdout. The expected operator flow:

```
docker run ... ghcr.io/wheelsdown/spivot-server:latest serve
...
████████████████████████████████████████████████████████████████████
  SPIVOT SERVER FIRST-RUN BOOTSTRAP
  ────────────────────────────────────────────────────────────────
  No administrator is registered. Use this server_registration
  invite to enroll the first user. Single-use, 24h expiry.

      <43-character base64url token>

████████████████████████████████████████████████████████████████████
```

The operator copies the token from container logs into the first
administrator's app. Subsequent restarts while the bootstrap invite is
still active stay silent. Once a user is registered, the bootstrap
path never runs again.

### Day-two invites

After bootstrap, any enrolled user can mint a `server_registration`
invite to onboard a new user over the API:

```bash
curl -sX POST https://spivot.example/v1/client-apps/invites \
  --cert client.pem --key client.key \
  -H 'Content-Type: application/json' -d '{"expires_in_seconds": 86400}'
```

The 201 response carries the plaintext `token` once (never retrievable
again); the new user redeems it through `POST /v1/client-apps/enroll`.
The scope is fixed to `server_registration` — the body cannot request
a different scope. Each invite is single-use, defaults to a 24-hour
lifetime (max 7 days), and is attributed to the minting user so
`GET /v1/client-apps/invites` can list a caller's own outstanding and
historical invites. A user may hold at most **10** outstanding
(unconsumed, unexpired) invites at once; the 11th returns `429` until
one is consumed or expires — a bound on a single compromised
credential being used as an account-minting faucet.

Operators without an enrolled session (or scripting unattended setup)
can still mint invites — including `journey`-scoped ones — directly
via the CLI:

```bash
spivot-server invite create                         # 24h server_registration invite
spivot-server invite create -scope journey -lifetime 168h    # 7 days
```

The CLI output includes the plaintext token, the scope, the expiration
time, and the stored token hash for audit correlation. CLI- and
bootstrap-issued invites have no minting user, so they do not appear
in any user's `GET /v1/client-apps/invites` list.

### Invite minting policy

`SPIVOT_INVITE_MINT_POLICY` (also `--invite-mint-policy`) controls who
may mint `server_registration` invites via
`POST /v1/client-apps/invites`:

- `any-user` *(default)* — any enrolled user may mint. Preserves the
  out-of-the-box behavior so a build upgrade never silently locks out
  a running client.
- `admin-only` — only the **founding administrator** may mint. The
  founding admin is the earliest-enrolled, non-disabled account (the
  one that consumed the first-run bootstrap invite). Promoting
  additional admins is future work.
- `denied` — the API mints for no one; the operator uses the
  CLI/shell.

The CLI `invite create` and the first-run bootstrap mint directly
through storage and are **never** gated by this policy — shell access
is the ultimate authority. The active mode is advertised at
`GET /v1/server` under `capabilities.registration.mint_policy` so
clients can show or hide an "invite a user" affordance; it is
intentionally kept out of the content-addressed policy document
(whose hash pins journey provenance), so flipping the mode does not
churn `policy_hash`.

> Security note: the default is `any-user` for upgrade continuity.
> Operators wanting least-privilege onboarding should set `admin-only`
> (or `denied` for CLI-only minting).
