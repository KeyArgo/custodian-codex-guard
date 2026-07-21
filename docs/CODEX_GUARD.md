# Custodian Guard for Codex

## What this is

The existing Custodian kernel, Paladin vault, and guard-adapter framework are
the foundation (see [custodian-kernel](https://github.com/KeyArgo/custodian-kernel)).
This repo is the Build Week contribution: a new Codex-native enforcement surface —

- a repo-local Codex plugin and governance skill;
- a dependency-free MCP server exposing `guard_action`, `verify_receipts`,
  and `list_receipts`;
- the ledger is kernel-internal, not agent-facing: every receipt and approval
  is stamped with the harness that produced it (server-side, never a
  model-supplied value), and no harness sees any receipts by default —
  not even its own. The agent being governed is exactly the party a denial
  log exists to constrain; letting it read its own reasons/tools/verdicts
  would turn the ledger into an oracle it could probe to learn the
  enforcement boundary and route around it. Visibility (a harness's own
  history, another adapter's, or both) is only ever something the operator
  grants explicitly via a `LedgerAccessPolicy` rule, managed from `custodian
  console`'s `[G]` key. Not physically separate storage (one shared,
  hash-chained receipt log, matching this module's existing tamper-evidence
  design) — isolation is enforced at the query boundary. The write path is
  fully kernel-mediated too: no MCP tool ever exposes a raw append/delete —
  `guard_action` is the only writer, and it appends only what the kernel's
  own decision logic computes, never arbitrary model-supplied content;
- action-bound, expiring, single-use human approvals that the model cannot grant;
- a typed coding-action risk model independent of the model's own label;
- fail-closed composition of workspace, secret, prompt-injection, and
  kernel-self-protection guards;
- value-free HMAC hash-chained decision receipts;
- a deterministic judge demo and adversarial regression suite.

## Threat model

Guard assumes the model may be mistaken, prompt-injected, context-starved, or
actively attempting to understate risk. It therefore does not trust the
caller's action label. Known tool and command shapes independently raise the
minimum risk class. Unknown classes deny; guard crashes deny; raw credential
material denies; paths outside the declared workspace deny; changes to policy,
vault, audit, or guard surfaces deny.

The current plugin governs actions routed through its MCP decision boundary.
It does not claim to replace the host operating system sandbox or intercept a
separate, unintegrated tool runner. Codex's own sandbox and approval controls
remain defense in depth.

Approval is intentionally an operator-terminal operation. For a friendly path,
run `custodian-codex approve latest`; it shows the requester, full bound digest,
and human-readable time remaining, then requires interactive confirmation. The
long `--digest` form remains available when the operator wants to compare the
value shown by Guard independently. Approval never executes the action: it only
authorizes that exact digest for one subsequent consumption.

Receipt and approval state directories are private on POSIX, symlink state
roots are rejected, and receipt appends are serialized across MCP processes on
Windows and POSIX. HMAC chaining detects modification by processes that do not
possess the local signing key; it is not a substitute for OS account isolation
against an attacker who controls both the receipt file and its key.
