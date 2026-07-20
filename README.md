# LAPS Delegation Audit

LAPS Delegation Audit is an open-source PowerShell tool designed to map Microsoft Legacy LAPS (LAPS 1) deployment and permissions across an Active Directory environment.

It identifies computers using LAPS, lists the accounts and groups allowed to read local administrator passwords, detects suspicious delegations, and generates a clear and interactive HTML report.

## 📸 Screenshot

[Preview] : [View Online Example](https://dakhama-mehdi.github.io/LAPS-Delegation-Audit/Example/Legacylapsreports.html)

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

## More Information

A complete technical explanation and practical demonstration are available in the following article:

[Active Directory Security: Audit LAPS Delegations and Detect ACL Vulnerabilities](https://www.it-connect.fr/audit-laps-delegation-active-directory/)

## Disclaimer

This tool is intended for authorized security auditing and defensive purposes only. Always test it in a controlled environment before using it in production.


