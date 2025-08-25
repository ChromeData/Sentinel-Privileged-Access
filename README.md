# Lab 04 — Privileged-Access Detections for Microsoft Sentinel

[![tests](https://github.com/ChromeData/Sentinel-Privileged-Access/actions/workflows/tests.yml/badge.svg)](https://github.com/ChromeData/Sentinel-Privileged-Access/actions/workflows/tests.yml)

**The PAM kill chain, written as Sentinel alerts. A dormant admin waking up, a
user granting themselves a role, a vault read at 3am — detections written by
someone who actually operates privileged access, not by a generic SOC.**

| | |
|---|---|
| **Domains** | Azure · CyberArk/Idira (identity threat model) |
| **Built on** | [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) (MIT) — schema + conventions |
| **Cost** | ~$1–3 (Log Analytics ingestion) · **Runtime** ~4 hours |
| **Status** | 🟡 Built, validated, not yet deployed |

---

## The point

A PAM engineer knows the privileged-access kill chain cold. Most Sentinel content
is written by SOC analysts working from a generic threat model. Detections written
by someone who *runs* privileged access catch things theirs don't — and that
difference is the whole brand.

## The four detections

| File | Fires when | Why it's a PAM insight |
|---|---|---|
| **dormant-privileged-account-reactivation** | an admin idle 30+ days suddenly signs in | abandoned-but-not-deprovisioned admins are the account PAM is supposed to own |
| **self-service-role-assignment** | someone grants themselves a privileged role | the `roleAssignments/write` escalation, watched for directly |
| **keyvault-bulk-secret-read** | one identity reads many secrets fast | vault enumeration — the thing CyberArk audit catches for free, rebuilt in KQL |
| **break-glass-off-hours** (hunt) | an emergency account is used outside hours | break-glass should be near-silent; any use is a question |

## Validated, not just written

[`scripts/validate.py`](./scripts/validate.py) schema-checks every detection the
way the upstream Azure-Sentinel CI does: required keys, severity enum, ATT&CK
tactic spelling, non-empty KQL, no placeholder GUIDs. **13 unit tests**, and one
of them runs the validator against every detection in the repo — so if any file
here regresses, CI goes red.

```bash
python -m pytest tests/ -v
python scripts/validate.py
```

Building this surfaced a real modeling bug: hunting queries have no `severity`
(they aren't alerts), so validating them with the detection schema wrongly failed
them. The validator now distinguishes the two — that fix is in the history and
it's the kind of detail that separates "wrote some YAML" from "understands the
product."

## What I didn't build

The Sentinel schema and validation conventions are Microsoft's. The detection
logic — the KQL, the thresholds, the choice of *what* to watch for — is the PAM
domain knowledge, and it's mine.

---

## Deploying

The detections import into Sentinel as Analytics Rules. Each references a
watchlist (`PrivilegedAccounts`, `BreakGlassAccounts`) so they're portable; swap
for `IdentityInfo` in a real tenant. Validate locally first, then import through
the portal or your Sentinel-as-code pipeline.

## Findings

`findings/` fills in once deployed against simulated activity.
[LAB-NOTES.md](./LAB-NOTES.md) is the log.

## License

Lab code: MIT ([LICENSE](./LICENSE)). Azure-Sentinel conventions stay MIT,
credited above.
