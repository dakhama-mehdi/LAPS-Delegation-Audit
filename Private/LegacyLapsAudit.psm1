
<#
.SYNOPSIS
    LAPS Audit & Exposure Detection Tool – scans your environment for misconfigurations, delegated permissions, and attack paths.

.DESCRIPTION
    Invoke-LapsReportsAD is a lightweight and RSAT-free audit tool designed to assess the security posture of your LAPS deployment.

    It verifies delegated permissions on sensitive LAPS attributes (`ms-Mcs-AdmPwd`, `ms-Mcs-AdmPwdExpirationTime`) across all root Organizational Units (OUs),
    identifies accounts with read access, and detects exposed attack paths or misconfigurations that could lead to credential compromise.

    The tool also audits all computers in each OU to detect missing LAPS-managed passwords, helping you ensure coverage and compliance across your machine fleet.

.AUTHOR
    Mehdi Dakhama

.CONTRIBUTOR
    Alain Cuisenier

.NOTES
    Version       : 1.2
    Requirements  : PowerShell 5.1+, Domain-joined machine with LDAP access
    Dependencies  : None (uses pure ADSI – no RSAT / no ActiveDirectory module)

.LINK
    https://github.com/dakhama-mehdi/LAPS-Delegation-Audit
#>


Function Invoke-Legacylapsreports { 

    [CmdletBinding()]
        param (
        [string]$Oupath,
        [string]$domainDn = $null,
        [string]$SavePath
        )

    $Bannercolor = "Cyan"
    $MSGcolor    = "DarkGreen"

   function Show-LapsBanner {
   param (
        [string]$BannerColor
    )
    Write-Host ""
    Write-Host "╔═════════════════════════════════════════════════════╗" -ForegroundColor $Bannercolor
    Write-Host "║                                                     ║" -ForegroundColor $Bannercolor
    Write-Host "║        Welcome to Legacy Laps Audit v1.4            ║" -ForegroundColor $Bannercolor
    Write-Host "║        Auditing Legacy Laps Deleguation & ACL       ║" -ForegroundColor $Bannercolor
    Write-Host "║                                                     ║" -ForegroundColor $Bannercolor
    Write-Host "╚═════════════════════════════════════════════════════╝" -ForegroundColor $Bannercolor
    Write-Host ""
    }

    Show-LapsBanner -BannerColor $Bannercolor

    # Script start: obtain the current date and time
    $startDate = Get-Date

    Start-Sleep -Seconds 2

    # Load modules and variables
    $varsPath = "$PSScriptRoot\variables.ps1"

    $Modulefunctions =  Join-Path -Path $PSScriptRoot -ChildPath "Function.psm1"
    Import-Module $Modulefunctions -Force

    # Retrieve LAPS attribute GUIDs from schema
    $lapsGuids = Get-LapsGuids

    # Check if the file exists before attempting to load it
    if (Test-Path $varsPath) {
    try {
        # Dot-source the file to import all variable declarations into the current scope
        .$varsPath
    } catch {
        # Catch and throw any error that occurs during import
        throw "Failed to load variables from '$varsPath': $($_.Exception.Message)"
    }
} 
    else {
    # Throw a clear error if the file is missing
    throw "Variables file not found at: $varsPath"
}
    
    # Domain name resolution if not provided
    if (-not $domainDn) {
    try {
    $domainDn = ([ADSI]"LDAP://RootDSE").defaultNamingContext
    Write-Host "Domain Found: $domainDn `r`n" -ForegroundColor Green
    sleep -Seconds 2
}
    catch {
    throw "Unable to detect the current domain. Verify that you are connected to an Active Directory domain."
}
}

    # Get root OU hierarchy and delegations 
    $rootOUs = Get-RootOrganizationalUnits -DomainDN $domainDn

    $result  = Get-LAPSDelegations -RootOUs $rootOUs -LapsGuids $lapsGuids

    $OUDelegationsMap    = $result.DelegationsMap
    $OUDelegationsReport = $result.DelegationsReport

    # Get custom OUPath
    if (-not $Oupath) {
       $rootOUs = $OUDelegationsMap.Keys.Clone()
    } 
    else {
    $rootOUs = $Oupath
    }

    # Default group to skiped

    # Well-known SIDs to always skip (translated to localized NTAccount names)
    $SkipSidList = @(
    'S-1-5-32-544' # Administrators
    'S-1-5-10',  # SELF
    'S-1-5-18'   # SYSTEM
    'S-1-5-11',  # Authenticated Users
    'S-1-1-0',  # Everyone
    'S-1-5-9'   # DC
    )

    $SkipAccounts = foreach ($sid in $SkipSidList) {
    try {
        (New-Object System.Security.Principal.SecurityIdentifier($sid)).Translate([System.Security.Principal.NTAccount]).Value
    } catch {
        # If translation fails, skip
        continue
    }
    }

    # Scan OU
    foreach ($ouDN in $rootOUs) {

    Write-Host "Scan $ouDN" -ForegroundColor Yellow

    $delegatedAccounts          =  $OUDelegationsMap[$ouDN]
    $effectiveDelegatedAccounts = @($delegatedAccounts.Clone())
    $effectiveDelegatedAccounts += @($SkipAccounts)


    # Get all computers from OU enabled with passwords laps
    $Haslaps = @(Get-ADSIComputers -SearchBaseDN $ouDN)

    $Configmachines += ($Haslaps).count

    # Counts nbrs of computer on OU
    $nbrallcomputers += Get-ADSIComputerCount -SearchBaseDN $ouDN

    foreach ($comp in $Haslaps) {
        $compDN   = $comp.DistinguishedName
        $compName = $comp.Name

        try {
            $entry = [ADSI]"LDAP://$compDN"
            $acl = $entry.psbase.ObjectSecurity
        } 
        catch {
            Write-Warning "Canot read ACL from computer $compDN"
        }

        # For each monitored LAPS attribute (ReadPassword, WritePassword, ExpiredTime)
        foreach ($guid in $lapsGuids.Keys) {

         $aceList = $acl.Access | Where-Object {

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
                         
         foreach ($entry in $aceList) {
                $account = try {
                    ($entry.IdentityReference.Translate([System.Security.Principal.NTAccount])).Value
                } catch {
                    $entry.IdentityReference.Value
                }

                # Skip if account is delegate in OU parent
                if ($effectiveDelegatedAccounts -contains $account) { continue }

                # Skip default SID
                if ($KnownSIDs -contains $account)  {
                continue
                }

                # Then, check deleguation parent OU
                $realOU   = $compDN -replace '^CN=[^,]+,', ''
                $isDelegatedInParent = Get-AccountDelegatedInParentOU -startingOU $realOU -accountToCheck $account -delegationMap $OUDelegationsMap -aclCache $OUACLCache
                
                if ($isDelegatedInParent) {
                    # Store in memory to skip redundant checks later
                    $effectiveDelegatedAccounts += $account
                } else {
                    # Detected anomaly: account is not delegated on the OU or any parent OU
 
                    $Anomalies += [PSCustomObject]@{
                        Computer          = $compName
                        UnexpectedAccount = $account
                        Attribut          = if ($entry.ObjectType.Guid -ne $guid) { "Generic All" } else { $lapsGuids[$guid] } # ex: ms-Mcs-AdmPwd
                        Permission        = ($entry.ActiveDirectoryRights -join ', ')
                        OU                = $realOU
                    }
                }

            }
        }
    }
    }

    $Allaccountsdelegate = $OUDelegationsMap.Values | ForEach-Object { $_ } | Select-Object -Unique

    $RootOUDelegationReports = $OUDelegationsReport | Group-Object OU, Account | ForEach-Object {
    
    # Get distinct permissions
    $rawPermissions = $_.Group | Select-Object -ExpandProperty Permission | Sort-Object -Unique

    # Logical transformation
    if ($rawPermissions -match 'GenericAll') {
        $finalPermission = 'Full Control'
    }
    elseif ($rawPermissions -match 'GenericWrite') {
        $finalPermission = 'WriteALL'
    }
    else {
        $finalPermission = ($rawPermissions -join ', ')
    }

    # Create final object
    [PSCustomObject]@{
        OU         = $_.Group[0].OU
        Account    = $_.Group[0].Account
        Attribut   = ($_.Group | Select-Object -ExpandProperty Attribut | Sort-Object -Unique) -join "`n"
        Permission = $finalPermission
    }
}

    # Suspicious delegation
    $GroupedAnomalies = $Anomalies | Group-Object Computer, UnexpectedAccount, OU | ForEach-Object {
    
    $allPermissions = ($_.Group | Select-Object -ExpandProperty Permission) -join ', '

    if ($allPermissions -match 'GenericAll') {
        $finalPermission = 'FC'
    }
    elseif ($allPermissions -match 'GenericWrite') {
        $finalPermission = 'WriteALL'
    }
    else {
        $finalPermission = ($_.Group | Select-Object -ExpandProperty Permission | Sort-Object -Unique) -join ', '
    }

    if ($finalPermission -match 'ExtendedRight|FC') { $risk = 'Excessive privilege' } 
    else { $risk = 'Misconfiguration' }

    [PSCustomObject]@{
        Computer          = $_.Group[0].Computer
        UnexpectedAccount = $_.Group[0].UnexpectedAccount
        OU                = $_.Group[0].OU
        Attribut          = ($_.Group | Select-Object -ExpandProperty Attribut | Sort-Object -Unique) -join "`n"
        Permission        = $finalPermission
        risk              = $risk
    }
}

    $nbremptycomputers = $nbrallcomputers - $Configmachines

    $date = (Get-Date)
    $domainname = (($domainDn -replace '^DC=', '') -replace ',DC=', '.' )

    $Scope = if ($Oupath) { $Oupath } else { "All domain" }

    Write-Host "`r"
    Write-Host "Suspicious ACL" -ForegroundColor Green
    $GroupedAnomalies | FT

    $DeleguateAccounts = @()

    $Allaccountsdelegate | Where-Object { $_ -notin $SkipAccounts } | ForEach-Object {
    $DeleguateAccounts  += Get-ADSIObjectInfo $_
    }

    $LapsOUDelegations = @()
    
    # Get all default Groups
    $skipdefaultgroups = $null
    $skipdefaultgroups = @()	
    $skipdefaultgroups += ([adsisearcher]"(&(groupType:1.2.840.113556.1.4.803:=1)(!(objectSID=S-1-5-32-546))(!(objectSID=S-1-5-32-545)))").findall().Properties.name
    $skipdefaultgroups += ([adsisearcher] "(&(objectCategory=group)(admincount=1)(iscriticalsystemobject=*))").FindAll().Properties.name
    $varoptionalgroup = [ADSI]("LDAP://" + (([ADSI]"LDAP://RootDSE").schemaNamingContext))
    $varoptionalgroup.PsBase.ObjectSecurity.Access.identityreference.value | select -Unique | ForEach-Object {

    $skipdefaultgroups += $_.Split("\")[1]
    }

    foreach ($ouDN in $OUACLCache.Keys) {

    $acl = $OUACLCache[$ouDN]
    #$acl = $OUACLCache["OU=server,OU=T0,DC=info,DC=lab"]

    $lapsACEs = $acl.Access | Where-Object {
        (
            # Case 1: ACE explicitly targeting the LAPS attribute
            ($_.ObjectType.Guid -eq $guid -and $_.AccessControlType -eq 'Allow' -and
             $_.ActiveDirectoryRights -match 'ReadProperty|ExtendedRight|ControlAccess|WriteProperty') -or
            # Case 2: Global ACE (no ObjectType specified)
            ($_.ObjectType.Guid -eq [guid]::Empty -and $_.AccessControlType -eq 'Allow' -and
             $_.ActiveDirectoryRights -match 'GenericAll|ExtendedRight')
        )


    }

    foreach ($ace in $lapsACEs) {
        $account = try {
            $ace.IdentityReference.Translate([System.Security.Principal.NTAccount])
        } catch {
            $ace.IdentityReference
        }

         # Exclusion de SELF

        if ($account -like "*\SELF") { continue }
        $dnaccount = $account.Value.Split("\")[1]
        if ($skipdefaultgroups -contains $dnaccount) {continue}


        $LapsOUDelegations += [PSCustomObject]@{
            OU         = $ouDN
            Account    = $account.ToString()
            Rights     = $ace.ActiveDirectoryRights -join ', '
            Attribute  = 'ms-Mcs-AdmPwd'
            Inherited  = $ace.IsInherited
        }
    }
}

    # Default Path %LOCALAPPDATA%\Temp
    $date1 = Get-Date -Format "MMddyy_HHmmss"
    if (-not $SavePath) {
    $SavePath = Join-Path $env:TEMP "Legacylapsreports_$date1.html"
    } else {
    $SavePath = $SavePath + "\Legacylapsreports_$date1.html"
    }
     
    # Calculate Elapsed Time
    
    $endDate = Get-Date
    $elapsedTime = New-TimeSpan -Start $startDate -End $endDate
    $elapsedTime = $($elapsedTime.ToString("hh\:mm\:ss"))

     Write-Host "Scanne $nbrallcomputers computers empty passwords $nbremptycomputers computers not config Elapsed : $elapsedTime Suspicious permissions $($Anomalies.count)" -ForegroundColor Cyan
     sleep -Seconds 2

     # Generate repport

Export-LapsHtmlReport `
    -TotalScanned $nbrallcomputers `
    -EmptyPasswords $nbremptycomputers `
    -SuspiciousDelegations $($GroupedAnomalies.count) `
    -Haspassword $Configmachines `
    -Date $date `
    -Domain $domainname `
    -Scope $Scope `
    -EmptyComputersTable $RootOUDelegationReports `
    -DelegationsTable $GroupedAnomalies `
    -AllDelegatedAccounts $DeleguateAccounts `
    -AlldelegationOU $LapsOUDelegations `
    -ElapsedTime $elapsedTime `
    -OutputPath $SavePath
}

# SIG # Begin signature block
# MIItjAYJKoZIhvcNAQcCoIItfTCCLXkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAnEXer0Cuk2TAl
# 7RkjcXxBoFJVwxj7QdHT9WI/yaBW+aCCEtUwggXJMIIEsaADAgECAhAbtY8lKt8j
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
# AQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCCbljUtI6xAOHodL8Zx
# I/oaq7390uzz3uoElQJBbwkDwTANBgkqhkiG9w0BAQEFAASCAYAfOIyGpl1+ZH1c
# GLr2p6mBuaPWWvn4v73ubptrfjLGGHQp/70bm9I2VeenT9WL5CY2QRtwx2Sb3UNY
# XhzHlAvxCX7I9waiB+AsT33rGR7fBTc3HW4eK5A0+yT4CSDSF3/qHpsCbUQkxjL0
# GRyu6GZ/4TX/EFsvZv16gaIrtld4ZVXS1KBcJnzQPVjq81ZrQP8JSWNA6ObWIjfh
# 3FUZZuhb7SjfRj0brR9Zb0srLQTmm/5dwyqNUFHAaYWmrzXt3e+dcG31CxbKCSa6
# YnpT6Mk0vPDXVFgwvG0cZDtTT6PG3Tf7239pvKboWbMbZN6aGurtt5I4toa2fj8+
# OUQzp6bcZrT4um6C1bN5XhiK6rBG0xxG7oYGowxyQtVw6BWNESIIwhpOUzZaxd7v
# dRVLF47aPavDwwz7k6zrE12mDqu75i9Dw+WcuWPSt9dhsds6JAFEwylJJHbPipWY
# oe/lfKsNqdqWE1UzSSHo2O6xghAtC3rQYp8TTbWt5satWRZKIuOhghd2MIIXcgYK
# KwYBBAGCNwMDATGCF2IwghdeBgkqhkiG9w0BBwKgghdPMIIXSwIBAzEPMA0GCWCG
# SAFlAwQCAQUAMHcGCyqGSIb3DQEJEAEEoGgEZjBkAgEBBglghkgBhv1sBwEwMTAN
# BglghkgBZQMEAgEFAAQgpQm8smP+LaajnXQ+JGy76lq96F6eyDm7lbuPTpK0gkEC
# EB9Org2WNzmhFZ13jETvqnkYDzIwMjYwNDI3MTMyMDMzWqCCEzowggbtMIIE1aAD
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
# hvcNAQkQAQQwHAYJKoZIhvcNAQkFMQ8XDTI2MDQyNzEzMjAzM1owKwYLKoZIhvcN
# AQkQAgwxHDAaMBgwFgQU3WIwrIYKLTBr2jixaHlSMAf7QX4wLwYJKoZIhvcNAQkE
# MSIEIGs3uzJGN64mKABXhXJKWGcdkKZPr3SPRbJnQTZrDFSlMDcGCyqGSIb3DQEJ
# EAIvMSgwJjAkMCIEIEqgP6Is11yExVyTj4KOZ2ucrsqzP+NtJpqjNPFGEQozMA0G
# CSqGSIb3DQEBAQUABIICALszinmpeBAkDAP2DDKt+hjQ3VmtiQ9XB3VYj2l+vQd4
# iZ7LnHnLM1yfQHqh/DhhQajCnZ34kruVLzol8W424tJwncoQOY0235tA3+ASGgbd
# DZ8xHsexD/AtSkkKV1l/Z4N7g/A63ZhhBM/0AtZPmdQSiVxoVpveLkCmfSOYYjWZ
# GOE9C1rwDa4V9agzp/U+a9cHleQGPLeU/0et/bt0XykW5Xt4Qrv9DKfpbi/Wzzck
# NJsAMMBMuLU+naXg32MPoB20kdgC75sTogly0cPYpId/BMwn9IdyLWpCqpaaRJdl
# abCm/TpkBTeA99xF9C5l/GsPLUk58vSbEy24zIo4sKv7AYr8FoWTo/6ZPWr/etks
# M2RVn4jKCV3Zwd10D1HOTeCpGDwl6vD98CBUI0k+Zr1YU0k365gyvt/igW8EnFK5
# BaDT6we1pgjfTEt00a7pdsz1MGgWItk3ToazDl1+Sp9XR7L8MyA1x0b9zTUqb66U
# VS4ZqPZ805M6Tiqzl2a8B10dRFsuZPKdTxG0fxpIMpXwAUpjR++piuvZBan2yxxr
# roLAwQeBXkFxYX10RKiGIiGmCmbPtJ8gHLH7Po8qizkXcCDtZzte3TT8yr/w95bI
# 1NP2eRKP2TNFbkNJWuCjvPbUBwUp/1caBZOM3F5VjG1sHE9Y2pCD/DjQt8iOKkkH
# SIG # End signature block
