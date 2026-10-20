# 🛡️ SOC Detection Engineering Lab

A Detection-as-Code engineering repository focusing on enterprise threat scenario identification, custom Sigma rule development, telemetry analysis (Windows/Sysmon), and automated translation into Splunk (SPL) and Elasticsearch (KQL) queries.

---

## 🎯 Architecture & Methodology

Modern enterprise Security Operations Centers (SOCs) leverage **Detection-as-Code** workflows to version-control, validate, and test alert logic before deployment to production SIEM environments.

```text
[Threat Modeling / MITRE ATT&CK] 
               ⬇
   [Sysmon Telemetry / Logs]
               ⬇
     [Sigma Rules (YAML)]
               ⬇
  [SIEM Queries (SPL / KQL)]

```

---

## 🔬 Detection Scenarios

| MITRE ATT&CK Technique | Scenario Title | Telemetry Source | Target Platform | Severity |
| --- | --- | --- | --- | --- |
| **T1059.001** | PowerShell Execution Policy Bypass & Download Cradle | Sysmon Event ID 1 (Process Creation) | Splunk SPL / Elastic KQL | **High** |
| **T1003.001** | Suspicious LSASS Process Access (Credential Dumping) | Sysmon Event ID 10 (Process Access) | Splunk SPL / Elastic KQL | **High** |
| **T1087 / T1016** | Active Directory & Domain Reconnaissance | Sysmon Event ID 1 (Process Creation) | Splunk SPL / Elastic KQL | **Medium** |

---

## 📁 Repository Structure

```text
├── rules/
│   ├── proc_creation_win_powershell_susp_download_bypass.yml
│   ├── proc_creation_win_powershell_susp_download_bypass_queries.md
│   ├── proc_access_win_lsass_susp_access.yml
│   └── proc_creation_win_susp_domain_recon.yml
├── logs/
│   └── powershell_download_bypass_sysmon_event1.json
└── README.md

```

---

## 🔍 Validation & Conversion

Rules are written adhering to the official Sigma specification. Example conversion to Splunk SPL:

```bash
# Convert PowerShell rule to Splunk SPL
sigma convert -t splunk -p sysmon rules/proc_creation_win_powershell_susp_download_bypass.yml

```

---

*Maintained by **Ahmet Furkan Hüsmek** | Cybersecurity & Detection Engineering Portfolio*


