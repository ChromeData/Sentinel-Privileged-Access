# Lab 04 — Privileged-Access Detections for Microsoft Sentinel

**A set of KQL analytics rules and hunting queries that detect privileged-access
abuse — the CyberArk/PAM threat model expressed in Azure's detection language —
validated against simulated activity in a lab workspace.**

| | |
|---|---|
| **Domains** | Azure · CyberArk/Idira (identity threat model) |
| **Built on** | [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) (MIT) — schema, structure, and detection conventions |
| **Runtime** | ~4 hours · ~$1–3 (Log Analytics ingestion for the lab window) |
| **Status** | 🟡 In progress |

---

## Why this lab exists

A PAM engineer knows the privileged-access kill chain cold: a dormant admin
suddenly authenticates, someone adds themselves to a privileged role, a break-glass
account is used outside a change window, credentials are read from a vault at an
odd hour. Most Sentinel content is written by SOC analysts. Detections written by
someone who actually operates privileged access are a different, sharper thing —
and that difference is exactly the profile you're building.

This lab turns that domain knowledge into working, schema-valid KQL, tested against
activity you generate on purpose so you can prove the rules fire.

## What I built

- **`detections/`** — analytics rules as YAML in the Azure-Sentinel repo format
  (so they could be submitted upstream), each targeting one privileged-access
  technique, mapped to MITRE ATT&CK.
- **`hunting/`** — broader KQL hunting queries for the same threat model.
- **A simulation script** that generates the benign-and-malicious activity each
  rule is meant to catch, so detection is demonstrated rather than assumed.
- A validation step that checks each YAML against the Sentinel schema before you
  ever open a PR.

## What I did not build

The Sentinel platform, the detection schema, and the KQL functions are Microsoft's.
My work is the detection logic, the ATT&CK mappings, the simulation harness, and
the analysis of true/false positive behavior.

---

## The detections

| Rule | Technique | MITRE | Data source |
|------|-----------|-------|-------------|
| Dormant privileged account reactivation | A long-idle admin authenticates | T1078.004 | SigninLogs |
| Self-service privileged role assignment | Principal adds itself to a privileged role | T1098 | AuditLogs |
| Break-glass account used outside change window | Emergency account login off-hours | T1078 | SigninLogs |
| Bulk secret retrieval from Key Vault | Abnormal volume of secret reads | T1552.001 | AzureDiagnostics / KeyVault |
| PIM activation without matching ticket | Elevation with no linked change | T1548 | AuditLogs |

Each lives in `detections/<name>.yaml` with the full query.

---

## Running it

### Prerequisites

```bash
az        >= 2.60
pwsh      >= 7.4
# A lab Log Analytics workspace with Microsoft Sentinel enabled.
# Entra ID diagnostic settings shipping SigninLogs + AuditLogs to it.
```

### Validate before deploying

```bash
make validate     # schema-check every detections/*.yaml against the Sentinel spec
```

### Deploy to your lab workspace

```bash
export WORKSPACE_ID=...            # lab workspace only
make deploy                        # creates the analytics rules via az CLI
```

### Prove they fire

```bash
make simulate     # generates the activity each rule targets
# wait for ingestion (a few minutes), then check Incidents in the portal
```

### Teardown

```bash
make destroy      # removes the deployed rules
```

---

## Findings

The analysis that makes this a lab and not a copy-paste:

| Rule | Fired on sim? | False positives in 24h baseline | Tuning applied |
|------|---------------|-------------------------------|----------------|
| | | | |

Questions worth answering:
- What's the false-positive rate against a quiet baseline? Which rule is noisiest?
- The dormant-account rule needs a lookback baseline — how long before it's
  reliable, and how do you handle a genuinely new admin?
- Which of these would a default Sentinel content pack already cover, and where
  does your PAM framing add something the stock rule misses?
- Could any of these become a real PR to Azure/Azure-Sentinel? (The schema
  validation is already there. That's the point.)

## What broke

See [LAB-NOTES.md](./LAB-NOTES.md).

## What I would do differently

_End._
