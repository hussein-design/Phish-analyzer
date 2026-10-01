# Architecture Rules

Permanent project constraints. Apply these to every task automatically —
do not wait for them to be restated in a prompt.

## Core design philosophy

- This tool is local-first and privacy-first by design: no telemetry,
  no mandatory cloud dependency, no data leaves the machine except
  explicit calls to threat-intel/sandbox APIs the user configures with
  their own keys.
- This principle is non-negotiable for this codebase. If a future
  feature request would require abandoning it (e.g. multi-tenant SaaS,
  mandatory hosted backend), stop and flag the conflict explicitly
  rather than silently compromising it. That kind of feature belongs in
  a separate project, not this one.

## External integrations (APIs, sandboxes, enrichment providers)

- All new external integrations are optional and feature-flagged via
  config. The tool must work with zero new API keys configured — missing
  keys degrade gracefully (skip the feature), never crash.
- All external calls are async (httpx/aiohttp) and must not block the
  main scan flow. Return the current verdict immediately; update results
  when async enrichment completes (background task / callback pattern).
- Every external call has an explicit timeout. No exceptions.
- Cache every external API response (keyed on URL, hash, domain, etc.)
  using the project's persistent L1 (in-memory) / L2 (SQLite-backed,
  survives restart) EnrichmentCache, with a TTL appropriate to how often
  that data changes. Propose and justify the TTL for anything new.
- When adding a new provider, follow the existing provider interface
  pattern already used by prior integrations — same async shape, same
  caching convention, same graceful-failure behavior. Do not invent a
  new pattern without a stated reason.

## Persistent data

- Any new persistent state (new tables, new columns) that represents
  application data the user would want preserved across updates MUST go
  through a proper Alembic migration. Never use ad-hoc
  `CREATE TABLE IF NOT EXISTS` for application data.
- Ad-hoc DDL is acceptable ONLY for pure infrastructure state with no
  user-facing meaning (e.g. a cache table that can be safely dropped and
  rebuilt). State explicitly which category new persistent state falls
  into before deciding how to create it.

## Scoring and verdict logic

- Each analysis dimension (static, dynamic, behavioral, BEC, and any
  future category) is scored independently and surfaced as its own
  named field with its own reasons list — never silently merged into one
  opaque number.
- Any change to how these independent scores combine into the overall
  verdict is a significant design decision. Present the proposed design
  (formula, thresholds, worked example) and wait for explicit approval
  BEFORE implementing it. Do not implement verdict-merging logic
  silently and report it as a fait accompli afterward.
- Document any known false-positive/false-negative risk of a new signal
  explicitly, in both code comments and the README — do not present
  detection heuristics as solved problems.

## UI parity

- Any new score, signal, or analysis result added to the backend/API
  MUST also be surfaced in the PySide6 desktop UI in the same change —
  not as a follow-up task. Backend-only features that are invisible in
  the UI are treated as incomplete, not done.

## Testing and documentation

- Every new service module gets unit tests with mocked responses/data —
  never real network calls or real DB state leaking between tests.
- Existing tests must continue passing unmodified unless a change
  intentionally alters prior behavior (and that alteration is called out
  explicitly, not buried in a diff).
- Every new config value, API key, or env var is documented in both
  README and `.env.example` in the same change that introduces it.

## Review process

- For any multi-step task, after completing a phase/step, report: what
  was built, what design decisions were made and why, and explicit
  confirmation against each acceptance criterion — not just a diff or a
  test pass count.
- When a task has an ambiguous or consequential design decision
  embedded in it (verdict merging, scoring weights, data retention,
  anything that changes external behavior), stop and present it for
  review rather than choosing silently and moving on.
- If asked to confirm something was done and it was not fully done, say
  so plainly, including when a prior claim (e.g. a commit message or
  summary) was imprecise. Do not retroactively justify an inaccurate
  claim — correct it.
