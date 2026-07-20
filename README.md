# LAPS Delegation Audit

LAPS Delegation Audit is an open-source PowerShell tool designed to map Microsoft Legacy LAPS (LAPS 1) deployment, permissions, and security risks across an Active Directory environment.

It identifies computers protected by LAPS, maps accounts and groups allowed to read local administrator passwords, and detects suspicious permissions applied directly to computer objects. The results are presented in a clear, interactive, and easy-to-understand HTML report.

## 📸 Screenshot
<img width="1747" height="530" alt="Image" src="https://github.com/user-attachments/assets/83b3288b-b7d9-46a1-accd-01fd212720dc" />

[Online Example] : [View Online Example](https://dakhama-mehdi.github.io/LAPS-Delegation-Audit/Example/Legacylapsreports.html)

## Features

- Maps Microsoft Legacy LAPS deployment
- Identifies computers using LAPS
- Lists accounts and groups allowed to read LAPS passwords
- Maps LAPS delegations by Organizational Unit
- Detects suspicious permissions applied directly to computer objects
- Provides information about delegated accounts
- Generates a clear and interactive HTML report
- Supports domain-wide and OU-specific audits
- Does not require administrative privileges

## Why?

To understand the risks, attack scenarios, and detection process, read the complete technical article:

[Active Directory Security: Audit LAPS Delegations and Detect ACL Vulnerabilities](https://www.it-connect.tech/active-directory-security-auditing-laps-delegations-and-detecting-acl-flaws/)

## Installation

Install the module from the PowerShell Gallery:

    Install-Module LegacyLapsAudit -Scope CurrentUser -Force

## Usage

Run a complete audit of the Active Directory domain:

    Invoke-LegacyLapsReports

Audit a specific Organizational Unit:

    Invoke-LegacyLapsReports -OUPath "OU=Computers,DC=contoso,DC=com"

Once the audit is complete, the HTML report opens automatically in the default web browser.

## HTML Report

The generated report provides:

- The number of computers analyzed
- The number of computers using Legacy LAPS
- All accounts and groups allowed to read LAPS passwords
- LAPS delegations grouped by Organizational Unit
- Suspicious ACLs applied directly to computer objects
- Additional information about delegated accounts and groups

## Requirements

- Windows PowerShell 5.1 or later
- Active Directory PowerShell module
- Access to an Active Directory domain

Administrative privileges are not required. However, using an account with permission to read LAPS attributes provides a more complete report.

## Credits

 - Alain Cuisenier
 - [https://www.doctorkloud](https://www.doctorkloud.fr/)
 - https://www.it-connect.fr/ 
