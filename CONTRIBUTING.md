# Contributing

Issues and pull requests are welcome. A few things are load-bearing rather than
matters of taste, so they are written down.

## The rules that are not negotiable

**No dependencies.** Node 24 built-ins only — `node:sqlite`, `node:test`,
`node:zlib`, and so on. No build step, no bundler, no transpiler. A patch that
adds a `dependencies` entry will be declined however good the library is; the
point of the project is that it installs nothing on a network where installing
things is a paperwork exercise. Vendored files (D3, the ATT&CK bundles) are the
exception and each one is accounted for in `NOTICE`.

**Tests, and the standard of proof.** Run `npm test` — it must pass. If you fix
a bug, add a test and then *break the fix* to confirm the test fails. A test
that passes with the behaviour removed is worse than no test, and this suite has
shipped a few of those; the comments naming them are there so it happens less.

**Nothing from a real network.** No routable addresses, no real hostnames, no
real people. `test/repo-hygiene.test.js` enforces what it can — documentation
ranges only (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), no `.mil` or
`.gov` domains, one tracked mission profile. Two of its checks read the mission
profile on the machine, so they skip on a clone; that is not permission.

## Style

Match the file you are editing. Comments explain *why*, especially the
non-obvious why — a comment that restates the code is noise, and one that
records the bug a line exists to prevent is the most useful thing in the file.

Commit messages: a summary line in the imperative, then prose explaining what
was wrong and why this fixes it. Look at `git log` before writing one.

## Running it

```bash
node bin/serve.js
```

Node 24 or newer. For the default model backend you also need the Claude Code
CLI installed and logged in; see the README for the API-key alternatives. The
terrain survey scripts need PowerShell 7, and the browser-driven tests and the
screenshot tool need Chrome or Edge on the machine.

## Things that would help

The backlog in `docs/BACKLOG.md` records what is known to be worth doing, with
the measurement behind each item. It is a better starting point than guessing.
