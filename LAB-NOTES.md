# Lab Notes, 04 Sentinel Privileged-Access Detections

Running log. Errors, dead ends, fixes, surprises. Dated, newest at the bottom.

---

## Format

```
### YYYY-MM-DD, what I was trying to do

**Expected:**
**Got:**
**Cause:**
**Fix:**
```

---

## Decisions and finds while building

### Hunting queries don't have a severity. The validator now knows that

First version required `severity` of every file. The break-glass hunting query
has none, correctly, because a hunting query is a saved search, not a scheduled
alert. Requiring severity of it was a category error. The validator now uses a
relaxed schema for anything under `hunting/`. Pinned by two tests.

### Real GUIDs, and a check that keeps them real

Every detection shipped with a placeholder GUID. Replaced all four with real
UUIDs, and the validator fails any `6f1a2b3c-0000...` placeholder, so a
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

### 2026-08-12, validator run against the shipped detections

**Expected:** all four files pass once I'd replaced the placeholder GUIDs.

**Got:**

```
FAILED tests/test_validate.py::TestShipped::test_all_shipped_detections_valid[break-glass-off-hours.yaml]
1 failed, 10 passed
```

**Cause:** I required `severity` of every file. `break-glass-off-hours.yaml` is a
*hunting* query and correctly has none, because a hunting query is a saved search, not
a scheduled alert. Requiring severity of it is a category error, and it was my
validator that was wrong, not the detection.

**Fix:** Split the schema. Anything under `hunting/` validates against a relaxed
required-key set; `detections/` still demands severity. Added two tests: one that a
hunting doc without severity passes, one that the *same* doc still fails as a
detection, so the relaxation has to be deliberate rather than accidental.

**Why I'm leaving this in the notes:** it's the difference between knowing the YAML
schema and knowing the product. The tool told me the file was broken. The file was
fine and my understanding was broken.

---

### 2026-08-12, placeholder GUIDs

All four detections shipped with `6f1a2b3c-0000-4d00-8000-lab...` IDs. Generated real
UUIDs for each. The validator now fails any remaining placeholder, so a copy-pasted
new detection can't carry one into a submission.

Final run: **13 passed** (`findings/test-run.txt`).

### 2026-08-12, the KQL runs now, and I was wrong about why it couldn't

I had this lab filed as permanently blocked: KQL needs a Log Analytics
workspace, a workspace needs a subscription, end of story.

That conflated two different things. **Sentinel** needs a subscription. The
**Kusto engine underneath Sentinel** does not, and Microsoft publishes it as a
container, free for dev and test:

```
docker run -d --name kustainer -e ACCEPT_EULA=Y -m 4G -p 8080:8080 \
  mcr.microsoft.com/azuredataexplorer/kustainer-linux:latest
```

So all four detections now execute for real. 11 tests, on top of the 13
structural ones.

**Every test plants decoys that must not fire**, and that is the whole value.
A rule returning the attack row is easy; a rule returning the attack row *and
nothing else* is a detection, and schema validation cannot tell the difference.
The decoys that matter most:

- **self-service**: a self-grant that *failed*. No escalation happened, so
  alerting on it trains the analyst to ignore the rule.
- **keyvault-bulk**: `SecretList` rather than `SecretGet`. Enumerating secret
  names is not reading their values, and conflating them alerts on every backup
  job that lists a vault.
- **dormant**: a *failed* sign-in. Counting those turns password-spray against a
  dormant admin into a "the account is back" alert, which inverts the meaning of
  the rule entirely.
- **break-glass**: 08:00 and 18:00 exactly, because the boundary is
  `< start or >= end` and an off-by-one either floods the hunt with 8am logins
  or hides a 6pm one.

Also confirmed the `=~` in the self-service rule is load-bearing: Entra is
inconsistent about UPN casing between `InitiatedBy` and `TargetResources`, so
switching it to `==` would silently stop detecting. There is now a test pinning
that.

**Two constraints worth being honest about.** `_GetWatchlist` is a Sentinel
function, not a Kusto one, and two of the four rules depend on it, so the
harness stubs it. And the fixture schema carries only the columns these queries
touch, so a query that passes here can still fail in a tenant by referencing a
column the fixture omits. Passing means the logic is sound, not that the rule is
deployed and working.

**One thing I added deliberately:** the CI job fails if the tests *skip* rather
than run. The harness skips when Kusto is unreachable, which is right locally
and wrong in CI, and without that guard a broken emulator would give a green job
that executed no KQL at all. That is the fifth time this repo has met the same
failure mode, so it is now something I build against by default rather than
notice afterwards.

Full detail in `findings/kusto-execution-run.txt`.

---

### 2026-08-12, the skip guard that was not wired up

First CI run after adding the Kusto tests failed: 13 passed, **11 errors**,
connection refused. The schema-validation job runs `pytest tests/`, which picks
up the execution tests, and there is no emulator in that job.

They were supposed to skip. The `pytestmark = pytest.mark.skipif(...)` was
declared in `kusto_harness.py`, the helper module. **pytest only collects
`pytestmark` from modules it collects as tests**, so it did nothing at all.

Same family as everything else here, inverted. Not a green result that checked
nothing, but a guard that looked present, read correctly in review, and was
never wired to anything. Moved into the test module; verified both directions:

```
with Kusto:     24 passed
without Kusto:  13 passed, 11 skipped
```

Testing the absent case is the part I nearly skipped. A skip guard is only
worth what its failure mode is worth, and the only way to know it works is to
run it in the condition it exists for.

---
