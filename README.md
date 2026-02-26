# LAPS-Delegation-Audit : Status : in progress

🛡️ PowerShell tool for detecting dangerous LAPS Legacy delegations allowing read access to LAPS Legacy passwords.

## 🔍 Features

- Detects delegated users/groups with read access to LAPS passwords
- Identifies suspicious or non-privileged accounts
- Scans a given OU or entire domain
- Generates a clean HTML report with KPIs

## 📸 Screenshot

[Preview] : [View Online Example](https://dakhama-mehdi.github.io/LAPS-Delegation-Audit/Example/Legacylapsreports.html)

## 📦 Usage

```powershell
.\LAPSDelegAudit.ps1 -OU "OU=Servers,DC=info,DC=lab"
