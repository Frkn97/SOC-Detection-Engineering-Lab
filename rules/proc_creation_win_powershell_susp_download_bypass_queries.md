# 🔍 SIEM Query Translations: Suspicious PowerShell Download Cradle

Derived from Sigma rule `proc_creation_win_powershell_susp_download_bypass.yml`.

---

## 1. Splunk (SPL)
Target: Sysmon (`EventCode=1`) or Security (`EventCode=4688`)

```spl
(index=windows OR index=sysmon) (EventCode=1 OR EventCode=4688) 
(Image="*\\powershell.exe" OR OriginalFileName="PowerShell.EXE")
(
    CommandLine="*-ep bypass*" OR 
    CommandLine="*-ExecutionPolicy Bypass*" OR 
    CommandLine="*-ExecutionPolicy Unrestricted*" OR 
    CommandLine="*-nop*" OR 
    CommandLine="*-NoProfile*" OR 
    CommandLine="*-w hidden*" OR 
    CommandLine="*-WindowStyle Hidden*"
)
(
    CommandLine="*DownloadString*" OR 
    CommandLine="*DownloadFile*" OR 
    CommandLine="*Net.WebClient*" OR 
    CommandLine="*Invoke-WebRequest*" OR 
    CommandLine="*iwr *" OR 
    CommandLine="*curl *" OR 
    CommandLine="*wget *" OR 
    CommandLine="*IEX*" OR 
    CommandLine="*Invoke-Expression*"
)
| table _time host User ParentImage Image CommandLine

```

---

## 2. Elasticsearch / Kibana (KQL)

Target: Elastic Agent Sysmon integration

```kql
process.name : "powershell.exe" and 
process.command_line : (
    "*-ep bypass*" or 
    "*-ExecutionPolicy Bypass*" or 
    "*-ExecutionPolicy Unrestricted*" or 
    "*-nop*" or 
    "*-NoProfile*" or 
    "*-w hidden*" or 
    "*-WindowStyle Hidden*"
) and 
process.command_line : (
    "*DownloadString*" or 
    "*DownloadFile*" or 
    "*Net.WebClient*" or 
    "*Invoke-WebRequest*" or 
    "*iwr *" or 
    "*curl *" or 
    "*wget *" or 
    "*IEX*" or 
    "*Invoke-Expression*"
)

```

