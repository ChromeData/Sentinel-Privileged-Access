# Lab Notes — 04 Sentinel Privileged-Access Detections

Running log. Errors, dead ends, fixes, surprises. Dated, newest at the bottom.

---

## Format

```
### YYYY-MM-DD — what I was trying to do

**Expected:**
**Got:**
**Cause:**
**Fix:**
```

---

## Decisions and finds while building

### Hunting queries don't have a severity — the validator now knows that

First version required `severity` of every file. The break-glass hunting query
has none, correctly, because a hunting query is a saved search, not a scheduled
alert. Requiring severity of it was a category error. The validator now uses a
relaxed schema for anything under `hunting/`. Pinned by two tests.

### Real GUIDs, and a check that keeps them real

Every detection shipped with a placeholder GUID. Replaced all four with real
UUIDs, and the validator fails any `6f1a2b3c-0000...` placeholder — so a
copy-pasted new detection can't sneak a placeholder into a submission.

### Watchlists over IdentityInfo, on purpose

The rules reference `_GetWatchlist('PrivilegedAccounts')` rather than
`IdentityInfo | where AssignedRoles ...`. Watchlists make the rules portable and
testable without a fully-populated identity graph. Note in the README says to
swap for IdentityInfo in a real tenant.

---

## Known traps (confirm on deployment)

- **Timezone in break-glass-off-hours.** `datetime_part("hour", ...)` uses the
  workspace timezone. If that's UTC and the team is US-based, "off hours" is
  wrong by 5-8h. Confirm the workspace TZ before trusting the window.
- **queryPeriod 90d on the dormancy rule.** Long lookbacks cost ingestion and
  can be slow. Confirm it runs inside the frequency window.
- **Watchlists must exist before import** or the rules error at first run with a
  message that doesn't obviously point at the missing watchlist.

---

## Open questions

- [ ] Do the rules fire cleanly against simulated sign-in / role-assignment data?
- [ ] False-positive rate on the bulk-secret-read rule for legit automation?
- [ ] Does the dormancy query perform acceptably over 90d in a busy tenant?
- [ ] Capture one screenshot of each rule firing for findings/.

---

## Log

_(first entry goes here on the first deployment)_
