# Lab Notes — Sentinel Privileged-Access Detections

> Running log, newest first.

---

## Known traps (pre-seeded — confirm or replace)

### Watchlists must exist before the rules run

`dormant-privileged-account-reactivation` and the break-glass hunt call
`_GetWatchlist('PrivilegedAccounts')` / `('BreakGlassAccounts')`. Create those
watchlists first or the query errors. In a real tenant, swap the watchlist for
`IdentityInfo | where AssignedRoles has_any (...)`.

### Ingestion latency is not instant

After `make simulate`, allow several minutes before expecting an incident.
SigninLogs and AuditLogs typically land within ~5–15 min but can lag. A rule that
"didn't fire" is often a rule that hasn't ingested yet — check the raw logs first.

### queryPeriod vs queryFrequency

The dormant-account rule looks back 90d but runs hourly. Get this pairing wrong and
you either miss events or reprocess the same ones into duplicate incidents. Worth
understanding the interaction rather than copying the numbers.

### Placeholder GUIDs will bounce a PR

Every rule ships with a `6f1a2b3c-0000-...` placeholder id. `make validate` flags
them. Replace with `uuidgen` output before deploying or submitting upstream.

### Timezone in the break-glass hunt

`datetime_part("hour", TimeGenerated)` uses the workspace timezone, which may be
UTC. If your business window is local, convert explicitly — an off-by-timezone
business-hours filter is a silent false-negative generator.

---

## YYYY-MM-DD — <first real entry>

**Goal:**

**What happened:**

```
```

**Why:**

**Fix:**

**Time lost:**

---

## Open questions

- [ ] False-positive rate of each rule against a 24h quiet baseline?
- [ ] Which of these overlaps with stock Sentinel content, and where does the PAM
      framing genuinely add coverage?
- [ ] Is the Key Vault baseline (5x hourly mean) the right shape, or should it be
      a proper anomaly function (series_decompose_anomalies)?

## What I would do differently

_End._
