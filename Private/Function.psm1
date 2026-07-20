
function Get-RootOrganizationalUnits {
    param (
        [Parameter(Mandatory)]
        [string]$DomainDN
    )

    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(objectClass=organizationalUnit)"
    $searcher.SearchScope = "OneLevel"
    $searcher.SearchRoot = "LDAP://$DomainDN"

    try {
        return $searcher.FindAll()
    } catch {
        throw "Error searching for root OUs for '$DomainDN' : $($_.Exception.Message)"
        return @()
    }
}

function Get-LapsGuids {
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $schemaNC = $rootDSE.schemaNamingContext

    $attributes = @('ms-Mcs-AdmPwd') #, 'ms-Mcs-AdmPwdExpirationTime')
    $lapsGuids = @{}

    foreach ($attr in $attributes) {
        $searcher = New-Object DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = "LDAP://$schemaNC"
        $searcher.Filter = "(lDAPDisplayName=$attr)"
        $searcher.PropertiesToLoad.Add("schemaIDGUID") | Out-Null

        $result = $searcher.FindOne()
        if ($result -and $result.Properties["schemaIDGUID"]) {
            $guid = New-Object Guid (,$result.Properties["schemaIDGUID"][0])
            $lapsGuids[$guid.Guid] = $attr
        } else {
            throw "schemaIDGUID not found for $attr"
        }
    }

    return [hashtable]$lapsGuids
}

function Get-LAPSDelegations {
    param(
        [Parameter(Mandatory)]
        [array]$RootOUs,

        [Parameter(Mandatory)]
        [hashtable]$LapsGuids
    )

    $OUDelegationsMap    = @{}
    $OUDelegationsReport = @()

    $IgnoredSIDs = @(
    'S-1-5-18',    # Local System
    'S-1-5-11',    # Authenticated Users
    'S-1-5-32-544',# Administrators (builtin)
    'S-1-5-32-545',# Users (builtin)
    'S-1-5-32-554',# Pre-Windows 2000 Compatible Access
    'S-1-5-32-548',# Account Operators
    'S-1-5-32-560',# Windows Authorization Access Group
    'S-1-5-32-551',# Backup Operators
    'S-1-5-32-552',# Replicators
    'S-1-5-32-549',# Server Operators
    'S-1-5-32-550',# Print Operators
    'S-1-5-32-559',# Performance Log Users
    'S-1-5-32-561',# Terminal Server License Servers
    'S-1-1-0',     # Everyone
    'S-1-5-9',     # Enterprise Domain Controllers
    'S-1-5-10',    # Principal Self
    'S-1-5-6'      # Service
)

    $domainSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.AccountDomainSid.Value
    $DomainAdminsSID     = "$domainSID-512"
    $EnterpriseAdminsSID = "$domainSID-519"
    $SchemaAdminsSID     = "$domainSID-518"

    $IgnoredSIDs += @($DomainAdminsSID, $EnterpriseAdminsSID, $SchemaAdminsSID)


    foreach ($ou in $RootOUs) {

        $ouDN = [string]$ou.Properties.distinguishedname[0]
        $lapsReaders = @()

        try {
            $entry = [ADSI]"LDAP://$ouDN"
            $acl = $entry.psbase.ObjectSecurity
        }
        catch {
            Write-Warning "canot read ACL on OU : $ouDN"
            $OUDelegationsMap[$ouDN] = @()
            $OUDelegationsReport += [PSCustomObject]@{
                OU         = $ouDN
                Account    = '[NA]'
                Attribut   = ''
                Permission = ''
            }
            continue
        }

        foreach ($guid in $LapsGuids.Keys) {

            $ace = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
    $_.IsInherited -eq $false -and (
        # Case 1: ACE explicitly targeting the LAPS attribute
        ($_.ObjectType.Guid -eq $guid -and
         $_.ActiveDirectoryRights -match 'ReadProperty|ExtendedRight|ControlAccess|WriteProperty') -or

        # Case 2: Global ACE (no ObjectType specified)
        ($_.ObjectType.Guid -eq [guid]::Empty -and
         $_.ActiveDirectoryRights -match 'GenericAll|ExtendedRight')
    )
            }
            
   foreach ($entry in $ace) {

             try {
        $sid = $entry.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
    } catch {
        $sid = $entry.IdentityReference.Value
    }

    if ($IgnoredSIDs -contains $sid.Value) {
        continue
    }

    # if not find, try to convert sid to samaccountname
    try {
        $account = $sid.Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        $account = $sid.Value
    }

                $lapsReaders += [PSCustomObject]@{
                    Account    = $entry.IdentityReference.Value
                    Attribut   = $LapsGuids[$guid]
                    Permission = ($entry.ActiveDirectoryRights -join ', ')
                }
            }
        }

        if ($lapsReaders.Count -gt 0) {
            $OUDelegationsMap[$ouDN] = $lapsReaders.Account

            foreach ($entry in $lapsReaders) {
                $OUDelegationsReport += [PSCustomObject]@{
                    OU         = $ouDN
                    Account    = $entry.Account
                    Attribut   = $entry.Attribut
                    Permission = $entry.Permission
                }
            }
        }
        else {
            $OUDelegationsMap[$ouDN] = @()
            $OUDelegationsReport += [PSCustomObject]@{
                OU         = $ouDN
                Account    = '[NA]'
                Attribut   = ''
                Permission = ''
            }
        }
    }

    return [PSCustomObject]@{
        DelegationsMap    = $OUDelegationsMap
        DelegationsReport = $OUDelegationsReport
    }
}

function Get-AccountDelegatedInParentOU {
    param (
        [string]$startingOU,
        [string]$accountToCheck,
        [hashtable]$delegationMap,
        [hashtable]$aclCache
    )

    #$startingOU = "OU=server,OU=T0,DC=info,DC=lab"
    #$accountToCheck = "info\GG_RH"
    #$delegationMap = $OUDelegationsMap
    #$aclCache = $OUACLCache

    $currentOU = $startingOU

    while ($currentOU -ne $null) {

        # If delegation for this OU is not yet known
        if (-not $delegationMap.ContainsKey($currentOU)) {

            # Check if ACL is already cached
            if (-not $aclCache.ContainsKey($currentOU)) {
                try {
                    #$ouAcl = Get-Acl -Path "AD:$currentOU"
                    $entry = [ADSI]"LDAP://$currentOU"
                    $ouAcl = $entry.psbase.ObjectSecurity
                    $aclCache[$currentOU] = $ouAcl
                } catch {
                    Write-Warning "Unable to read ACL for OU $currentOU"
                    $delegationMap[$currentOU] = @()
                    break
                }
            }

            $ouAcl = $aclCache[$currentOU]

            # Extract accounts with access to ms-Mcs-AdmPwd
            $delegated = $ouAcl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and (
                    # Case 1: ACE explicitly targeting a LAPS attribute
                    ($_.ObjectType.Guid -in $lapsGuids.Keys -and
                     $_.ActiveDirectoryRights -match 'ReadProperty|ExtendedRight|ControlAccess|WriteProperty') -or

                    # Case 2: Generic ACE without attribute targeting
                    ($_.ObjectType.Guid -eq [Guid]::Empty -and
                     $_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|GenericRead|ReadProperty')
                )
            } | ForEach-Object {
                try { ($_.IdentityReference.Translate([System.Security.Principal.NTAccount])).Value }
                catch { $_.IdentityReference.Value }
            } | Select-Object -Unique

            $delegationMap[$currentOU] = $delegated | Select-Object -Unique
        }

        # Direct comparison
        if ($delegationMap[$currentOU] -contains $accountToCheck) {
            return $true
        }

        # Move up one level in the OU hierarchy
        if ($currentOU -match '^OU=[^,]+,(.+)$') {
            $currentOU = $Matches[1]
        } else {
            break
        }
    }

    return $false
}

function Get-ADSIComputers {
    param(
        [Parameter(Mandatory)]
        [string]$SearchBaseDN
    )

    # Prepare the ADSI search
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.SearchRoot  = "LDAP://$SearchBaseDN"
    $searcher.Filter      = "(objectClass=computer)"
    $searcher.PageSize    = 2000
    $searcher.SearchScope = "Subtree"

    # Filter: computers enabled + LAPS present
    $searcher.Filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(ms-Mcs-AdmPwd=*))"

    # Load only necessary properties
    $searcher.PropertiesToLoad.Add("distinguishedname") | Out-Null
    $searcher.PropertiesToLoad.Add("name") | Out-Null
    $searcher.PropertiesToLoad.Add("objectsid") | Out-Null

    # Search
    $results = $searcher.FindAll()

    # Convert to PScustom
    foreach ($entry in $results) {
        [PSCustomObject]@{
            DistinguishedName = $entry.Properties['distinguishedname'][0]
            Name              = $entry.Properties['name'][0]
            ObjectSID         = $entry.Properties['objectsid'][0]
        }
    }
}

function Get-ADSIComputerCount {
    param (
        [Parameter(Mandatory)]
        [string]$SearchBaseDN
    )

    # Filtre : all enabled machines
    $LdapFilter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot  = "LDAP://$SearchBaseDN"
        $searcher.Filter      = $LdapFilter
        $searcher.SearchScope = "Subtree"
        $searcher.PageSize    = 2000
        $searcher.PropertiesToLoad.Clear()

        return $searcher.FindAll().Count
    }
    catch {
        Write-Warning "Error Ldap on '$SearchBaseDN' : $_"
        return 0
    }
}

function Get-ADSIObjectInfo {
    param (
        [string]$SamAccountName
    )

    if ($SamAccountName -match '\\') {
        $Sam = $SamAccountName.Split('\')[1]
    } else {
        $Sam = $SamAccountName
    }

    $searcher = New-Object DirectoryServices.DirectorySearcher
    $searcher.Filter = "(samAccountName=$Sam)"
    $result = $searcher.FindOne()

    if (-not $result) {
        return [PSCustomObject]@{
            SamAccountName = $Sam
            Type           = 'Unknown'
            Enabled        = $null
            Created        = $null
            AdminCount     = $null
        }
    }

    $entry    = $result.GetDirectoryEntry()
    $props    = $entry.Properties
    $class    = $props["objectClass"] | Select-Object -Last 1
    $category = $props["objectCategory"][0]


    # Déterminer le type
    if ($category -like "CN=Computer*") {
        $type = "Computer"
    }
    elseif ($category -like "CN=Person*" -or $class -eq "user") {
        $type = "User"
    }
    elseif ($category -like "CN=Group*") {
        $type = "Group"
    }
    elseif ($class -eq "msDS-GroupManagedServiceAccount") {
        $type = "gMSA"
    }
    else {
        $type = $class
    }

    # Récupération des infos utiles
    $enabled = $null
    $created = $null
    $adminCount = $null

    try {
        if ($props["userAccountControl"]) {
            $uac = $props["userAccountControl"][0]
            $enabled = -not ($uac -band 2)  # 2 = ACCOUNTDISABLE
        }

        if ($props["whenCreated"]) {
            $created = [datetime]$props["whenCreated"][0]
        }

        if ($type -eq "User" -or $type -eq "Group" -and $props["adminCount"]) {
            $adminCount = $props["adminCount"][0]
        }
    } catch {
        # silently fail
    }

    return [PSCustomObject]@{
        SamAccountName = $Sam
        Type           = $type
        Enabled        = $enabled
        Created        = $created
        AdminCount     = if ($adminCount) { "True" } else {  }
    }
}

function Export-LapsHtmlReport {
    param (
        [Parameter(Mandatory)]
        [int]$TotalScanned,
        [int]$EmptyPasswords,
        [int]$SuspiciousDelegations,
        [int]$Haspassword,
        $Date,
        [String]$Scope,
        [String]$Domain,
        [array]$EmptyComputersTable,
        [array]$DelegationsTable,
        [array]$AllDelegatedAccounts,
        [array]$AlldelegationOU,
        $ElapsedTime,
        [string]$OutputPath = "LAPS-Audit-Report.html"
    )

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LAPS Audit Report</title>
<style>
body { font-family: sans-serif; margin: 20px; background: #f9f9f9; }
h1 { margin-bottom: 30px; }
.banner-container {
  display: flex; gap: 15px; flex-wrap: wrap; margin-bottom: 30px;
}
.banner {
  background-color: #4CAF50; color: white; padding: 20px;
  flex: 1; min-width: 150px; border-radius: 10px; text-align: center;
  box-shadow: 0 2px 5px rgba(0,0,0,0.2);
}
.banner.red { background-color: #f44336; }
.banner.orange { background-color: #ff9800; }
.banner.blue { background-color: #2196f3; }
a.viewlink {
  display: inline-block; margin: 10px 0 10px 0; color: #007bff;
  text-decoration: underline; cursor: pointer;
}
table {
  width: 100%; border-collapse: collapse; margin-top: 10px;
}
th, td {
  padding: 8px 12px; border: 1px solid #ccc;
}
th {
  background: #333; color: white;
}
</style>
<script>
function toggleVisibility(id) {
  var section = document.getElementById(id);
  section.style.display = (section.style.display === "none") ? "block" : "none";
}
</script>
<script>
function filterTable(inputId, tableId) {
  var input = document.getElementById(inputId);
  var filter = input.value.toUpperCase();
  var table = document.getElementById(tableId);
  var tr = table.getElementsByTagName("tr");

  for (var i = 1; i < tr.length; i++) {
    var row = tr[i];
    var text = row.textContent || row.innerText;
    row.style.display = text.toUpperCase().indexOf(filter) > -1 ? "" : "none";
  }
}
</script>
</head>

<body>

<div style="display: flex; justify-content: space-between; align-items: flex-end; border-bottom: 1px solid #ccc; padding-bottom: 8px; margin-bottom: 16px;">
  <div>
    <h1 style="margin: 0;">Legacy LAPS Delegation Audit</h1>
    <p style="margin: 0; font-size: 14px; color: #666;">Domain: <strong>$Domain</strong></p>
    <p style="margin: 0; font-size: 14px; color: #666;">Scope: <strong>$Scope</strong></p>
  </div>
  <div style="text-align: right; font-size: 13px; color: #666;">
    <div>
      <p style="margin: 0; font-size: 14px; color: #666;">Report date : <strong>$date</strong></p>
      <p style="margin: 0; font-size: 14px; color: #666;">Elapsed Time : <strong>$ElapsedTime</strong></p>
    </div>
  </div>
</div>


<div class="banner-container">
  <div class="banner blue">
    <div style="font-size: 24px;">$TotalScanned</div>
    <div>Total machines scanned</div>
  </div>
  <div class="banner orange">
    <div style="font-size: 24px;">$EmptyPasswords</div>
    <div>No LAPS password found</div>
  </div>
  <div class="banner red">
    <div style="font-size: 24px;">$SuspiciousDelegations</div>
    <div>Suspicious delegations</div>
  </div>
  <div class="banner">
    <div style="font-size: 24px;">$Haspassword</div>
    <div>LAPS password found</div>
  </div>
</div>
"@

    # SECTION 1 – Root deleguation
    $html += @"
<a class="viewlink" onclick="toggleVisibility('oudeleg')">⬇ View Root Delegations</a>
<div id="oudeleg" style="display: block;">
  <table>
    <tr><th>OU</th><th>Account</th><th>Attribute</th><th>Permission</th></tr>
"@
    foreach ($row in $EmptyComputersTable) {
        $html += "    <tr><td>$($row.OU)</td><td>$($row.Account)</td><td>$($row.Attribut)</td><td>$($row.Permission)</td></tr>`n"
    }

    $html += "</table></div>"

    # SECTION 2 – Suspicious ACL
    $html += @"
<a class="viewlink" onclick="toggleVisibility('suspect')">⬇ View Suspicious ACL</a>
<div id="suspect" style="display: block;">
<div style="display: flex; justify-content: space-between; align-items: center;">
  <h2 style="margin: 0;">Suspicious ACL</h2>
  <input type="text" id="searchSuspect" onkeyup="filterTable('searchSuspect', 'tableSuspect')" placeholder="Search..."
         style="padding: 6px 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; width: 240px;">
</div>

  <table id="tableSuspect">
    <tr><th>Computer</th><th>Account</th><th>Attribute</th><th>Permission</th><th>OU</th><th>Severity</th></tr>
"@

    foreach ($row in $DelegationsTable) {
        $html += "    <tr><td>$($row.Computer)</td><td>$($row.UnexpectedAccount)</td><td>$($row.Attribut)</td><td>$($row.Permission)</td><td>$($row.OU)</td><td>$($row.Risk)</td></tr>`n"
    }

    $html += "</table></div>"

    # SECTION 3 – All delegated accounts
    $html += @"
<a class="viewlink" onclick="toggleVisibility('allaccounts')">⬇ View All Delegated Accounts</a>
<div id="allaccounts" style="display: block;">
  <h2>All LAPS Delegated Accounts</h2>
  <table>
    <tr><th>Account</th><th>Type</th><th>Enabled</th><th>Created</th><th>Is admin</th></tr>
"@
    foreach ($row in $AllDelegatedAccounts) {
        $html += "    <tr><td>$($row.SamAccountName)</td><td>$($row.Type)</td><td>$($row.Enabled)</td><td>$($row.Created)</td><td>$($row.AdminCount)</td></tr>`n"
    }

    $html += "</table></div>"

    # SECTION 4 – ALL deleguations by OU
    $html += @"
<a class="viewlink" onclick="toggleVisibility('delegOU')">⬇ View OU Delegations</a>
<div id="delegOU" style="display: block;">
<div style="display: flex; justify-content: space-between; align-items: center;">
  <h2 style="margin: 0;">All delegations by OU</h2>
  <input type="text" id="searchDelegOU" onkeyup="filterTable('searchDelegOU', 'tableDelegOU')" placeholder="Search..."
         style="padding: 6px 10px; border: 1px solid #ccc; border-radius: 6px; font-size: 14px; width: 240px;">
</div>

  <table id="tableDelegOU">
    <tr><th>OU</th><th>Account</th><th>Rights</th><th>Attribute</th><th>Inherited</th></tr>
"@

    foreach ($row in $AlldelegationOU) {
        $html += "    <tr><td>$($row.OU)</td><td>$($row.Account)</td><td>$($row.Rights)</td><td>$($row.Attribute)</td><td>$($row.inherited)</td></tr>`n"
    }

    $html += @"
    </table>
    </div>

    <hr style="margin-top: 40px; border-top: 1px solid #ccc;" />
    <div style="font-size: 12px; color: #888; text-align: center; padding-top: 10px; padding-bottom: 30px;">
    Developed by <strong>Dakhama Mehdi</strong> &amp; <strong>Alain Cuisenier</strong> – <a href="https://github.com/dakhama-mehdi/LAPS-Delegation-Audit" target="_blank">GitHub</a><br />
    Credit <a href="https://www.doctorkloud.fr/" target="_blank">Doctor Kloud</a> Community for their support.<br />
    Special thanks to <a href="https://www.it-connect.fr/" target="_blank">IT-Connect</a> for their valuable resources.<br />
    @Copyright 2026 - Version 1.4
    </div>

</body>
</html>
"@

    $html += "</table></div></body></html>"

    # Export to file
    $html | Set-Content -Encoding UTF8 -Path $OutputPath
    Write-Host "Report generated at: $OutputPath" -ForegroundColor Green
    start $OutputPath
}
# SIG # Begin signature block
# MIItjAYJKoZIhvcNAQcCoIItfTCCLXkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCOYLHIKEW3Mdnq
# uRlCmJO/PPr1t+XDDhvHJT872Tu9JKCCEtUwggXJMIIEsaADAgECAhAbtY8lKt8j
# AEkoya49fu0nMA0GCSqGSIb3DQEBDAUAMH4xCzAJBgNVBAYTAlBMMSIwIAYDVQQK
# ExlVbml6ZXRvIFRlY2hub2xvZ2llcyBTLkEuMScwJQYDVQQLEx5DZXJ0dW0gQ2Vy
# dGlmaWNhdGlvbiBBdXRob3JpdHkxIjAgBgNVBAMTGUNlcnR1bSBUcnVzdGVkIE5l
# dHdvcmsgQ0EwHhcNMjEwNTMxMDY0MzA2WhcNMjkwOTE3MDY0MzA2WjCBgDELMAkG
# A1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVzIFMuQS4xJzAl
# BgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEkMCIGA1UEAxMb
# Q2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMIICIjANBgkqhkiG9w0BAQEFAAOC
# Ag8AMIICCgKCAgEAvfl4+ObVgAxknYYblmRnPyI6HnUBfe/7XGeMycxca6mR5rlC
# 5SBLm9qbe7mZXdmbgEvXhEArJ9PoujC7Pgkap0mV7ytAJMKXx6fumyXvqAoAl4Va
# qp3cKcniNQfrcE1K1sGzVrihQTib0fsxf4/gX+GxPw+OFklg1waNGPmqJhCrKtPQ
# 0WeNG0a+RzDVLnLRxWPa52N5RH5LYySJhi40PylMUosqp8DikSiJucBb+R3Z5yet
# /5oCl8HGUJKbAiy9qbk0WQq/hEr/3/6zn+vZnuCYI+yma3cWKtvMrTscpIfcRnNe
# GWJoRVfkkIJCu0LW8GHgwaM9ZqNd9BjuiMmNF0UpmTJ1AjHuKSbIawLmtWJFfzcV
# WiNoidQ+3k4nsPBADLxNF8tNorMe0AZa3faTz1d1mfX6hhpneLO/lv403L3nUlbl
# s+V1e9dBkQXcXWnjlQ1DufyDljmVe2yAWk8TcsbXfSl6RLpSpCrVQUYJIP4ioLZb
# MI28iQzV13D4h1L92u+sUS4Hs07+0AnacO+Y+lbmbdu1V0vc5SwlFcieLnhO+Nqc
# noYsylfzGuXIkosagpZ6w7xQEmnYDlpGizrrJvojybawgb5CAKT41v4wLsfSRvbl
# jnX98sy50IdbzAYQYLuDNbdeZ95H7JlI8aShFf6tjGKOOVVPORa5sWOd/7cCAwEA
# AaOCAT4wggE6MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLahVDkCw6A/joq8
# +tT4HKbROg79MB8GA1UdIwQYMBaAFAh2zcsH/yT2xc3tu5C84oQ3RnX3MA4GA1Ud
# DwEB/wQEAwIBBjAvBgNVHR8EKDAmMCSgIqAghh5odHRwOi8vY3JsLmNlcnR1bS5w
# bC9jdG5jYS5jcmwwawYIKwYBBQUHAQEEXzBdMCgGCCsGAQUFBzABhhxodHRwOi8v
# c3ViY2Eub2NzcC1jZXJ0dW0uY29tMDEGCCsGAQUFBzAChiVodHRwOi8vcmVwb3Np
# dG9yeS5jZXJ0dW0ucGwvY3RuY2EuY2VyMDkGA1UdIAQyMDAwLgYEVR0gADAmMCQG
# CCsGAQUFBwIBFhhodHRwOi8vd3d3LmNlcnR1bS5wbC9DUFMwDQYJKoZIhvcNAQEM
# BQADggEBAFHCoVgWIhCL/IYx1MIy01z4S6Ivaj5N+KsIHu3V6PrnCA3st8YeDrJ1
# BXqxC/rXdGoABh+kzqrya33YEcARCNQOTWHFOqj6seHjmOriY/1B9ZN9DbxdkjuR
# mmW60F9MvkyNaAMQFtXx0ASKhTP5N+dbLiZpQjy6zbzUeulNndrnQ/tjUoCFBMQl
# lVXwfqefAcVbKPjgzoZwpic7Ofs4LphTZSJ1Ldf23SIikZbr3WjtP6MZl9M7JYjs
# NhI9qX7OAo0FmpKnJ25FspxihjcNpDOO16hO0EoXQ0zF8ads0h5YbBRRfopUofbv
# n3l6XYGaFpAP4bvxSgD5+d2+7arszgowggZHMIIEL6ADAgECAhA12OBytW+cTayv
# VHUpRhwLMA0GCSqGSIb3DQEBCwUAMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhB
# c3NlY28gRGF0YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNp
# Z25pbmcgMjAyMSBDQTAeFw0yNTExMTYxMTAwMTlaFw0yNjExMTYxMTAwMThaMG0x
# CzAJBgNVBAYTAkZSMQ8wDQYDVQQHDAZUb3Vsb24xHjAcBgNVBAoMFU9wZW4gU291
# cmNlIERldmVsb3BlcjEtMCsGA1UEAwwkT3BlbiBTb3VyY2UgRGV2ZWxvcGVyLCBE
# QUtIQU1BIE1FSERJMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAp6Ku
# m/VmkWCqAaF/3zHh9f1FuJYY2ozbXOu7mo1/Q8i1c0fE0TXpkZXLY2GZbfpj9BmH
# AAFM0IhOsPR2vdxq3jOUJUb9TICneFor6YaPpySsXR3WSE7X42kgpkkmPELovm1Y
# hwSzhJ4a+E+NWL/MU8h5JpmGVlqPJ02/ZTlMj5kcpIQtq8hoQMcUEDkGFt9IcamE
# 1yN4IHkBA5nm4jJPaos0IuS77t805992JSGWhxBxWARH+2vyltv8Rmq1pZV1lE6n
# JgrWT7Ichjw2X/A+OP68ooTzQwCIpzXb4UuUcwHEfrmP3HGMQJoj//SNC4QPMao+
# 3Z8zbevl73E3d6Kfvra1S+pWM2Ze5YCsIqAd98GUHgi5E6GiG8FQq/+d6msL7l8B
# UASCqXlcAKIjRNMHp8BrUaaW6HS9Kpc+3O3t/LUmK6X3FFiW8QsWoh4K+7YSpopa
# CQbNXmEI4xftctwBOJrEU2oqRnYiwchfjqBNlrGwVGPK1rmM0iTt5KiLTus7AgMB
# AAGjggF4MIIBdDAMBgNVHRMBAf8EAjAAMD0GA1UdHwQ2MDQwMqAwoC6GLGh0dHA6
# Ly9jY3NjYTIwMjEuY3JsLmNlcnR1bS5wbC9jY3NjYTIwMjEuY3JsMHMGCCsGAQUF
# BwEBBGcwZTAsBggrBgEFBQcwAYYgaHR0cDovL2Njc2NhMjAyMS5vY3NwLWNlcnR1
# bS5jb20wNQYIKwYBBQUHMAKGKWh0dHA6Ly9yZXBvc2l0b3J5LmNlcnR1bS5wbC9j
# Y3NjYTIwMjEuY2VyMB8GA1UdIwQYMBaAFN10XUwA23ufoHTKsW73PMAywHDNMB0G
# A1UdDgQWBBSXTmfHi9BD9GDRwk5/doNtKHBXYzBLBgNVHSAERDBCMAgGBmeBDAEE
# ATA2BgsqhGgBhvZ3AgUBBDAnMCUGCCsGAQUFBwIBFhlodHRwczovL3d3dy5jZXJ0
# dW0ucGwvQ1BTMBMGA1UdJQQMMAoGCCsGAQUFBwMDMA4GA1UdDwEB/wQEAwIHgDAN
# BgkqhkiG9w0BAQsFAAOCAgEAe+khGqwUUkFYuFRsrvenX2/a+PIt2Tu9d3VoW6Or
# MX3YLpe7S2CgFkXwEi2Siq5KiD1labP9jsh/3G1ZQwwlnPv8dB7ocl/nOrQ9OZex
# GVE1r7IO6VYVa5F7XuJ/KadKLEbQSs1BpBVhESo1ZYr6w9NCLuO9q2Sh3H5MktET
# D6sB+g1TFOYMdwYl8eAawgI2kGPe3dRQSoumP0mHkm3x5SIwRCW+08md5uyzCIui
# 85WmcNPtM1QCqjkSpfdFGYPsnf/BO9NATpZkqFxhXwa9+PqseX+mofCIL49guCXG
# kU4RpeRHcUie14oYkxvBw7VUO4MT6wYbS2C3j2nyoAV4XqqNMfrhZIBJG5haj2RB
# V46bMJ+DsW6hxlm3lIlCaJT2pLbbk79OP+Bk0HIdC9mAbKzcqaZpBpn4+ljrcx7/
# X7OHv4XTCCDWwlZbaogy4Wci6TiSjjfpfXK5N/eJTEEh2w4qoYTTrR61ptkVnTUT
# vGRfPnVtS/3aOm2v4UahtOc/ygcL0A/J85r1e6CEeOaTm9eJbHoNdwNIYaZ81VlX
# /V/MoJgFCtioYOKiTf2Rdq7XrEEHLU2YGwCqJyKYz9tz10yXBcMW6/+gX+PGqAYz
# eKg5jbKLdi9lVrKspQUXAPHdcl6VJMXy799J0lbsQeJNgBVy6HWxOWvdLBGX3hPE
# 3aYwgga5MIIEoaADAgECAhEAmaOACiZVO2Wr3G6EprPqOTANBgkqhkiG9w0BAQwF
# ADCBgDELMAkGA1UEBhMCUEwxIjAgBgNVBAoTGVVuaXpldG8gVGVjaG5vbG9naWVz
# IFMuQS4xJzAlBgNVBAsTHkNlcnR1bSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTEk
# MCIGA1UEAxMbQ2VydHVtIFRydXN0ZWQgTmV0d29yayBDQSAyMB4XDTIxMDUxOTA1
# MzIxOFoXDTM2MDUxODA1MzIxOFowVjELMAkGA1UEBhMCUEwxITAfBgNVBAoTGEFz
# c2VjbyBEYXRhIFN5c3RlbXMgUy5BLjEkMCIGA1UEAxMbQ2VydHVtIENvZGUgU2ln
# bmluZyAyMDIxIENBMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnSPP
# BDAjO8FGLOczcz5jXXp1ur5cTbq96y34vuTmflN4mSAfgLKTvggv24/rWiVGzGxT
# 9YEASVMw1Aj8ewTS4IndU8s7VS5+djSoMcbvIKck6+hI1shsylP4JyLvmxwLHtSw
# orV9wmjhNd627h27a8RdrT1PH9ud0IF+njvMk2xqbNTIPsnWtw3E7DmDoUmDQiYi
# /ucJ42fcHqBkbbxYDB7SYOouu9Tj1yHIohzuC8KNqfcYf7Z4/iZgkBJ+UFNDcc6z
# okZ2uJIxWgPWXMEmhu1gMXgv8aGUsRdaCtVD2bSlbfsq7BiqljjaCun+RJgTgFRC
# tsuAEw0pG9+FA+yQN9n/kZtMLK+Wo837Q4QOZgYqVWQ4x6cM7/G0yswg1ElLlJj6
# NYKLw9EcBXE7TF3HybZtYvj9lDV2nT8mFSkcSkAExzd4prHwYjUXTeZIlVXqj+ea
# YqoMTpMrfh5MCAOIG5knN4Q/JHuurfTI5XDYO962WZayx7ACFf5ydJpoEowSP07Y
# aBiQ8nXpDkNrUA9g7qf/rCkKbWpQ5boufUnq1UiYPIAHlezf4muJqxqIns/kqld6
# JVX8cixbd6PzkDpwZo4SlADaCi2JSplKShBSND36E/ENVv8urPS0yOnpG4tIoBGx
# VCARPCg1BnyMJ4rBJAcOSnAWd18Jx5n858JSqPECAwEAAaOCAVUwggFRMA8GA1Ud
# EwEB/wQFMAMBAf8wHQYDVR0OBBYEFN10XUwA23ufoHTKsW73PMAywHDNMB8GA1Ud
# IwQYMBaAFLahVDkCw6A/joq8+tT4HKbROg79MA4GA1UdDwEB/wQEAwIBBjATBgNV
# HSUEDDAKBggrBgEFBQcDAzAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vY3JsLmNl
# cnR1bS5wbC9jdG5jYTIuY3JsMGwGCCsGAQUFBwEBBGAwXjAoBggrBgEFBQcwAYYc
# aHR0cDovL3N1YmNhLm9jc3AtY2VydHVtLmNvbTAyBggrBgEFBQcwAoYmaHR0cDov
# L3JlcG9zaXRvcnkuY2VydHVtLnBsL2N0bmNhMi5jZXIwOQYDVR0gBDIwMDAuBgRV
# HSAAMCYwJAYIKwYBBQUHAgEWGGh0dHA6Ly93d3cuY2VydHVtLnBsL0NQUzANBgkq
# hkiG9w0BAQwFAAOCAgEAdYhYD+WPUCiaU58Q7EP89DttyZqGYn2XRDhJkL6P+/T0
# IPZyxfxiXumYlARMgwRzLRUStJl490L94C9LGF3vjzzH8Jq3iR74BRlkO18J3zId
# mCKQa5LyZ48IfICJTZVJeChDUyuQy6rGDxLUUAsO0eqeLNhLVsgw6/zOfImNlARK
# n1FP7o0fTbj8ipNGxHBIutiRsWrhWM2f8pXdd3x2mbJCKKtl2s42g9KUJHEIiLni
# 9ByoqIUul4GblLQigO0ugh7bWRLDm0CdY9rNLqyA3ahe8WlxVWkxyrQLjH8ItI17
# RdySaYayX3PhRSC4Am1/7mATwZWwSD+B7eMcZNhpn8zJ+6MTyE6YoEBSRVrs0zFF
# IHUR08Wk0ikSf+lIe5Iv6RY3/bFAEloMU+vUBfSouCReZwSLo8WdrDlPXtR0gicD
# nytO7eZ5827NS2x7gCBibESYkOh1/w1tVxTpV2Na3PR7nxYVlPu1JPoRZCbH86gc
# 96UTvuWiOruWmyOEMLOGGniR+x+zPF/2DaGgK2W1eEJfo2qyrBNPvF7wuAyQfiFX
# LwvWHamoYtPZo0LHuH8X3n9C+xN4YaNjt2ywzOr+tKyEVAotnyU9vyEVOaIYMk3I
# eBrmFnn0gbKeTTyYeEEUz/Qwt4HOUBCrW602NCmvO1nm+/80nLy5r0AZvCQxaQ4x
# ghoNMIIaCQIBATBqMFYxCzAJBgNVBAYTAlBMMSEwHwYDVQQKExhBc3NlY28gRGF0
# YSBTeXN0ZW1zIFMuQS4xJDAiBgNVBAMTG0NlcnR1bSBDb2RlIFNpZ25pbmcgMjAy
# MSBDQQIQNdjgcrVvnE2sr1R1KUYcCzANBglghkgBZQMEAgEFAKB8MBAGCisGAQQB
# gjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcC
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCDUatD9rRLZVJ+UFWhb
# 3fL5nWOTNhJX+daD0OB288lMAjANBgkqhkiG9w0BAQEFAASCAYBjhjxvC1ei0T6/
# NAh0+G8ql6fOLwFVGlt6dDeymSC8080qgOZj1a9b0vrxcC+75AmAhhC9ipU8dq+B
# Jw2B+ipO2TLDnnYVIDcnYHS40ypfc+WfIQZLKWXZt0818LqJIKdiAi7JZdmQ8TP0
# x2fUA0w/NEPLmGzDbcFKBop7mA8T/KF5naaMjmkWN90dFQD9QLsNJfxbuThkJqaV
# Xw9n7rmyL4p2sxxEyGKjckQfl72JL2IQ4j8/rFdPk4/MBbZg+w5q+DKfnCKv19l8
# HqJdcfOZHINy9IhT0R0JqRqrVBEsF1PFTcHW6pwsi46tIBCKv3LtiUFabRfKuGuc
# eZq/HL/HytWHziz0jePgr9zMFWwcE1RtJZPlenfnHb5PB6DwNdY9IpkqGoVFPJS7
# RQd+0Vy+3SSgbTjL5UE69EPV7qG4fQ22ycmXelRjMddIPHekAqaO80Ri54pfvh+a
# XJHMI54sS4jgKfblmQMURRBOvkpLNi0VCg67UG11YxLQAI97vyyhghd2MIIXcgYK
# KwYBBAGCNwMDATGCF2IwghdeBgkqhkiG9w0BBwKgghdPMIIXSwIBAzEPMA0GCWCG
# SAFlAwQCAQUAMHcGCyqGSIb3DQEJEAEEoGgEZjBkAgEBBglghkgBhv1sBwEwMTAN
# BglghkgBZQMEAgEFAAQgEdBYqnCaQmziwqly8+Wye0WlMyYUGKkkdOeUYaA8nwkC
# EE2Mj4Oute72dJb2aZOXVEoYDzIwMjYwNDI3MTMyMDI5WqCCEzowggbtMIIE1aAD
# AgECAhAKgO8YS43xBYLRxHanlXRoMA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQg
# VHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEw
# HhcNMjUwNjA0MDAwMDAwWhcNMzYwOTAzMjM1OTU5WjBjMQswCQYDVQQGEwJVUzEX
# MBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lDZXJ0IFNIQTI1
# NiBSU0E0MDk2IFRpbWVzdGFtcCBSZXNwb25kZXIgMjAyNSAxMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEA0EasLRLGntDqrmBWsytXum9R/4ZwCgHfyjfM
# GUIwYzKomd8U1nH7C8Dr0cVMF3BsfAFI54um8+dnxk36+jx0Tb+k+87H9WPxNyFP
# JIDZHhAqlUPt281mHrBbZHqRK71Em3/hCGC5KyyneqiZ7syvFXJ9A72wzHpkBaMU
# Ng7MOLxI6E9RaUueHTQKWXymOtRwJXcrcTTPPT2V1D/+cFllESviH8YjoPFvZSjK
# s3SKO1QNUdFd2adw44wDcKgH+JRJE5Qg0NP3yiSyi5MxgU6cehGHr7zou1znOM8o
# dbkqoK+lJ25LCHBSai25CFyD23DZgPfDrJJJK77epTwMP6eKA0kWa3osAe8fcpK4
# 0uhktzUd/Yk0xUvhDU6lvJukx7jphx40DQt82yepyekl4i0r8OEps/FNO4ahfvAk
# 12hE5FVs9HVVWcO5J4dVmVzix4A77p3awLbr89A90/nWGjXMGn7FQhmSlIUDy9Z2
# hSgctaepZTd0ILIUbWuhKuAeNIeWrzHKYueMJtItnj2Q+aTyLLKLM0MheP/9w6Ct
# juuVHJOVoIJ/DtpJRE7Ce7vMRHoRon4CWIvuiNN1Lk9Y+xZ66lazs2kKFSTnnkrT
# 3pXWETTJkhd76CIDBbTRofOsNyEhzZtCGmnQigpFHti58CSmvEyJcAlDVcKacJ+A
# 9/z7eacCAwEAAaOCAZUwggGRMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFOQ7/PIx
# 7f391/ORcWMZUEPPYYzoMB8GA1UdIwQYMBaAFO9vU0rp5AZ8esrikFb2L9RJ7MtO
# MA4GA1UdDwEB/wQEAwIHgDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDCBlQYIKwYB
# BQUHAQEEgYgwgYUwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBdBggrBgEFBQcwAoZRaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3J0
# MF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNy
# bDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQEL
# BQADggIBAGUqrfEcJwS5rmBB7NEIRJ5jQHIh+OT2Ik/bNYulCrVvhREafBYF0RkP
# 2AGr181o2YWPoSHz9iZEN/FPsLSTwVQWo2H62yGBvg7ouCODwrx6ULj6hYKqdT8w
# v2UV+Kbz/3ImZlJ7YXwBD9R0oU62PtgxOao872bOySCILdBghQ/ZLcdC8cbUUO75
# ZSpbh1oipOhcUT8lD8QAGB9lctZTTOJM3pHfKBAEcxQFoHlt2s9sXoxFizTeHihs
# QyfFg5fxUFEp7W42fNBVN4ueLaceRf9Cq9ec1v5iQMWTFQa0xNqItH3CPFTG7aEQ
# JmmrJTV3Qhtfparz+BW60OiMEgV5GWoBy4RVPRwqxv7Mk0Sy4QHs7v9y69NBqycz
# 0BZwhB9WOfOu/CIJnzkQTwtSSpGGhLdjnQ4eBpjtP+XB3pQCtv4E5UCSDag6+iX8
# MmB10nfldPF9SVD7weCC3yXZi/uuhqdwkgVxuiMFzGVFwYbQsiGnoa9F5AaAyBjF
# BtXVLcKtapnMG3VH3EmAp/jsJ3FVF3+d1SVDTmjFjLbNFZUWMXuZyvgLfgyPehwJ
# VxwC+UpX2MSey2ueIu9THFVkT+um1vshETaWyQo8gmBto/m3acaP9QsuLj3FNwFl
# Txq25+T4QwX9xa6ILs84ZPvmpovq90K8eWyG2N01c4IhSOxqt81nMIIGtDCCBJyg
# AwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUw
# NTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2N
# DZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qft
# JYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0t
# rj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX
# 0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEp
# NVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coW
# J+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdk
# DjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0Xb
# Qcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sf
# uZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7v
# QTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwb
# tmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/n
# upiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3Bggr
# BgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAX
# zvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQ
# a8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd
# 6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FH
# aoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOc
# zgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFb
# qrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z
# 4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT
# 70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43es
# aUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif
# /sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+
# VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBY0wggR1oAMCAQICEA6b
# GI750C3n79tQ4ghAGFowDQYJKoZIhvcNAQEMBQAwZTELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEk
# MCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4XDTIyMDgwMTAw
# MDAwMFoXDTMxMTEwOTIzNTk1OVowYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERp
# Z2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMY
# RGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0MIICIjANBgkqhkiG9w0BAQEFAAOCAg8A
# MIICCgKCAgEAv+aQc2jeu+RdSjwwIjBpM+zCpyUuySE98orYWcLhKac9WKt2ms2u
# exuEDcQwH/MbpDgW61bGl20dq7J58soR0uRf1gU8Ug9SH8aeFaV+vp+pVxZZVXKv
# aJNwwrK6dZlqczKU0RBEEC7fgvMHhOZ0O21x4i0MG+4g1ckgHWMpLc7sXk7Ik/gh
# YZs06wXGXuxbGrzryc/NrDRAX7F6Zu53yEioZldXn1RYjgwrt0+nMNlW7sp7XeOt
# yU9e5TXnMcvak17cjo+A2raRmECQecN4x7axxLVqGDgDEI3Y1DekLgV9iPWCPhCR
# cKtVgkEy19sEcypukQF8IUzUvK4bA3VdeGbZOjFEmjNAvwjXWkmkwuapoGfdpCe8
# oU85tRFYF/ckXEaPZPfBaYh2mHY9WV1CdoeJl2l6SPDgohIbZpp0yt5LHucOY67m
# 1O+SkjqePdwA5EUlibaaRBkrfsCUtNJhbesz2cXfSwQAzH0clcOP9yGyshG3u3/y
# 1YxwLEFgqrFjGESVGnZifvaAsPvoZKYz0YkH4b235kOkGLimdwHhD5QMIR2yVCkl
# iWzlDlJRR3S+Jqy2QXXeeqxfjT/JvNNBERJb5RBQ6zHFynIWIgnffEx1P2PsIV/E
# IFFrb7GrhotPwtZFX50g/KEexcCPorF+CiaZ9eRpL5gdLfXZqbId5RsCAwEAAaOC
# ATowggE2MA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFOzX44LScV1kTN8uZz/n
# upiuHA9PMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6enIZ3zbcgPMA4GA1UdDwEB
# /wQEAwIBhjB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
# LmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNydDBFBgNVHR8EPjA8MDqg
# OKA2hjRodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEA
# cKC/Q1xV5zhfoKN0Gz22Ftf3v1cHvZqsoYcs7IVeqRq7IviHGmlUIu2kiHdtvRoU
# 9BNKei8ttzjv9P+Aufih9/Jy3iS8UgPITtAq3votVs/59PesMHqai7Je1M/RQ0Sb
# QyHrlnKhSLSZy51PpwYDE3cnRNTnf+hZqPC/Lwum6fI0POz3A8eHqNJMQBk1Rmpp
# VLC4oVaO7KTVPeix3P0c2PR3WlxUjG/voVA9/HYJaISfb8rbII01YBwCA8sgsKxY
# oA5AY8WYIsGyWfVVa88nq2x2zm8jLfR+cWojayL/ErhULSd+2DrZ8LaHlv1b0Vys
# GMNNn3O3AamfV6peKOK5lDGCA3wwggN4AgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMQIQCoDvGEuN
# 8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKCB0TAaBgkqhkiG9w0BCQMxDQYLKoZI
# hvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDQyNzEzMjAyOVowKwYLKoZIhvcN
# AQkQAgwxHDAaMBgwFgQU3WIwrIYKLTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkE
# MSIEIHJilRNkzl0Q+sgoCKC9nPJWGooWjJljgZh0lZ3Us+qpMDcGCyqGSIb3DQEJ
# EAIvMSgwJjAkMCIEIEqgP6Is11yExVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0G
# CSqGSIb3DQEBAQUABIICAJRBuoc2UBDJ1eiaSkGdb/de9DzjgBrrXzu36IsJ9sfY
# nRHHyg0YIztNLJC2TUZ4RsEcdZy6LM1uPK3cMLnSRZ2DVOZjzePsgyZ6tqST5j9p
# 662jk3dPbRZ2Z/lEjCLueDJLyzGCHVcPiu0CE6RcR9m54LFS51dnPTEz8rrWLt/R
# g6jH9rEipy3igKN0BG/937sY/wKYJQWfVVZ7Fqc+gGOR3fGnRbEO2Sx+/SbHrd1P
# sJusOk95BWHkf770YO6jIoPvDYNRLc0oXUgNbkHB4qcJp4y1bDQ/VN9qi0YE2GV1
# 3RtKaPI9ZKYJLaQXEJE4Xcrba03NIoZG9r75fwbjWIMtkCOqg3TTpA0RbHh5oKqh
# OAEK3SEXt4/y5Fjyn7mN4vI3509IjbmypMv4AxR0yljjqxev6vTNsotKfl0vp4Yu
# dyvzuq0oX8Xx+nAzB+OGULebl6ZKjWmFO2Y2ok9jdJ8Eo115Dd+kMEmmtJKA64+2
# qbbd+fHLVWCkYcz0i8hGqk/ZFUadR05bK5P4QyZ4K3oNs0AkJaQoqkXn7i1pMbaO
# cWGbDYzd3Vj74jK5YLzVlZyESqBD/iXtvtS+/oL0rYn/Qq+h2XHTCTd9EuYkjXwM
# dtXB7kZn/0RDgECjRNrgWwhMqsM+CcavK9ICdjw61SlNLH3M22ygc/3KIASpByid
# SIG # End signature block
