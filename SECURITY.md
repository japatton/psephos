# Security

## Reporting a vulnerability

Use GitHub's **private vulnerability reporting** on this repository (Security →
Report a vulnerability). Please do not open a public issue for anything that
would let somebody read a case file they should not.

This is a single-maintainer project. Expect an acknowledgement within a week
and no formal SLA beyond that. There is no bounty.

## What this tool is, for threat-modelling purposes

A Node process on a team's own network that holds live incident data — findings,
host verdicts, direct messages, uploaded evidence files — in a local SQLite
database, and shells out to a model to help work that evidence.

## The threat model it is built to, stated plainly

**Trusted LAN, attributed users, no hostile clients.** Inside that boundary the
design is deliberate; outside it, the tool is not what you want.

- **The server binds `0.0.0.0` by default** so teammates can reach it. Anyone who
  can reach the port and holds a token can read every unreviewed finding and can
  spend your model quota by starting sessions. Set `HUNT_HOST=127.0.0.1` if you
  did not mean to share it.
- **A member token is attribution, not authorisation.** It decides who you are,
  so an audit row can say who adjudicated what. It does not decide what you may
  see. The one exception is private channels: direct messages and groups are
  membership-checked on every read, on the SSE broadcast, and on the route that
  serves an attachment's bytes.
- **There is no TLS and no token rotation.** Put it behind a reverse proxy if you
  need either.
- **The `hunt_token` cookie is not `HttpOnly`, and application pages carry no
  Content-Security-Policy.** Script execution on this origin is therefore token
  theft. Uploaded files are served `Content-Type: application/octet-stream` with
  `nosniff`, a `sandbox` CSP and an attachment disposition, so an uploaded
  `.html` cannot execute; every record field reaching the DOM is escaped, and
  the markdown renderer escapes before parsing and scheme-checks link targets.
  Those are the mitigations. An XSS anywhere on the origin defeats them.
- **The store is owner-only.** `data/hunt.db` holds every member token in
  plaintext alongside the case file; it and its backups are chmodded `0600`.
- **Rate limits** are per caller address: 10 sign-in attempts a minute, 20 model
  turns a minute. They are there to make a mistake cheap, not to stop an
  attacker who is already inside the boundary.

## The model subprocess

A turn spawns the Claude CLI with `--strict-mcp-config`, an exhaustive
`--disallowedTools` denylist, and an empty working directory, so it starts with
no tools at all and gains only the typed hunt tools this application serves over
its own MCP server. The reasoning is in `README.md` ("How the Claude subprocess
is contained") and the properties are asserted in `test/invariants.test.js`
against the arguments the spawn actually receives.

The application never reads your Claude credentials. If you configure an API key
instead, it is stored `0600`, never logged, never returned to the browser, and
readable by exactly two modules — asserted by the same test file.

## Out of scope

- Anything requiring an attacker already on the LAN with a valid token. That is
  inside the trust boundary by design; if it matters to you, this tool is the
  wrong shape.
- Denial of service against your own server.
- The Claude CLI, the model, and anything the model says. A model proposal is a
  pending candidate until a person confirms it — that is the whole design.
- Findings a model gets wrong. See above.
