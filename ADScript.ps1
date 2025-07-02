#Script Information
#    This script performs a comprehensive Active Directory security audit.
#SYNOPSIS
#    This PowerShell script automates the collection of various Active Directory configurations
#    and security-related information. It organizes the output into categorized subdirectories.
#
#USAGE
#    To run this script, open a PowerShell console as an Administrator and execute:
#    .\ADScript.ps1
#
#    The script will create an 'ADResults_yyyyMMdd_HHmmss' folder in the same directory as the script,
#    containing various audit reports categorized into subfolders.


$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$BasePath = Join-Path $PSScriptRoot "ADResults_$timestamp"
$ReportPath = Join-Path $BasePath "AuditResults"
$GPOReportPath = Join-Path $BasePath "GPOReports"
$ForestDomainDir = Join-Path $BasePath "ForestDomain"
$SecurityPoliciesDir = Join-Path $BasePath "SecurityPolicies"
$PrivGroupsDir = Join-Path $BasePath "PrivilegedGroups"
$AccountAuditDir = Join-Path $BasePath "AccountAudit"
$AdvSecurityDir = Join-Path $BasePath "AdvancedSecurity"
$GPODir = Join-Path $BasePath "GPO"
$SystemInfoDir = Join-Path $BasePath "SystemInfo"
$LogFile = Join-Path $ReportPath "ScriptLog.txt"

# Create directories
$dirs = @($BasePath, $ReportPath, $GPOReportPath, $ForestDomainDir, $SecurityPoliciesDir, $PrivGroupsDir, $AccountAuditDir, $AdvSecurityDir, $GPODir, $SystemInfoDir)
foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Logging function
function Log-Message {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $LogFile -Append
}

# Command execution with error handling
function Execute-Command {
    param (
        [scriptblock]$command,
        [string]$outputFile
    )
    try {
        & $command | Out-File -FilePath $outputFile -Encoding UTF8
        Log-Message "Executed: $command"
    } catch {
        Log-Message "Error: $command - $_"
    }
}

# Host and system info
Execute-Command { hostname } "$SystemInfoDir\Hostname.txt"
Execute-Command { ipconfig /all } "$SystemInfoDir\IPConfig.txt"
Execute-Command { Get-WmiObject Win32_ComputerSystem | Select-Object Domain, Name, Manufacturer, Model | Format-List } "$SystemInfoDir\SystemSummary.txt"
Execute-Command { Get-WmiObject Win32_OperatingSystem | Format-List } "$SystemInfoDir\OperatingSystem.txt"
Execute-Command { netstat -ano } "$SystemInfoDir\NetworkPorts.txt"

# Forest and Domain Information
Execute-Command { Get-ADForest } "$ForestDomainDir\ForestInfo.txt"
Execute-Command { Get-ADDomain } "$ForestDomainDir\DomainInfo.txt"
Execute-Command { Get-ADDomainController -Filter * } "$ForestDomainDir\DomainControllers.txt"
Execute-Command { netdom query fsmo } "$ForestDomainDir\FSMORoles.txt"
Execute-Command { Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName } "$ForestDomainDir\OrganizationalUnits.txt"
Execute-Command { Get-ADTrust -Filter * } "$ForestDomainDir\TrustRelationships.txt"
Execute-Command { Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem, Site, IsGlobalCatalog, IsReadOnly | Export-Csv -Path "$ForestDomainDir\DC_List.csv" -NoTypeInformation } "$ForestDomainDir\DCListExport.txt"
Execute-Command { Get-ADDomain | Select-Object InfrastructureMaster, PDCEmulator, RIDMaster } "$ForestDomainDir\DomainRoles.txt"
Execute-Command { Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster } "$ForestDomainDir\ForestRoles.txt"

# Password and Security Policies
Execute-Command { Get-ADDefaultDomainPasswordPolicy } "$SecurityPoliciesDir\DefaultDomainPasswordPolicy.txt"
Execute-Command { Get-ADFineGrainedPasswordPolicy -Filter * } "$SecurityPoliciesDir\FineGrainedPasswordPolicies.txt"
Execute-Command { net accounts /domain } "$SecurityPoliciesDir\AccountLockoutPolicy.txt"
Execute-Command { Get-ADDefaultDomainPasswordPolicy | Format-List } "$SecurityPoliciesDir\DefaultDomainPasswordPolicy_Formatted.txt"
Execute-Command { Get-ADFineGrainedPasswordPolicy -Filter * | Format-List } "$SecurityPoliciesDir\FineGrainedPasswordPolicies_Formatted.txt"
Execute-Command { net accounts /domain } "$SecurityPoliciesDir\AccountLockoutPolicy_Formatted.txt"

# Privileged Group Auditing
Execute-Command { Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\DomainAdmins.txt"
Execute-Command { Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\EnterpriseAdmins.txt"
Execute-Command { Get-ADGroupMember -Identity 'Schema Admins' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\SchemaAdmins.txt"
Execute-Command { Get-ADGroupMember -Identity 'Administrators' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\Administrators.txt"

# Account Auditing
$InactiveDate = (Get-Date).AddDays(-90)
$PwdDate = (Get-Date).AddDays(-90)
Execute-Command { Get-ADUser -Filter 'Name -like "svc*"' -Properties Name, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires | Select-Object Name, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires } "$AccountAuditDir\ServiceAccounts.txt"
Execute-Command { Get-ADUser -Filter "Enabled -eq \$true -and LastLogonDate -lt \$InactiveDate" -Properties LastLogonDate | Select-Object Name, SamAccountName, LastLogonDate } "$AccountAuditDir\InactiveUsers.txt"
Execute-Command { Get-ADUser -Filter "Enabled -eq \$true -and PasswordNeverExpires -eq \$true" -Properties PasswordNeverExpires | Select-Object Name, SamAccountName, PasswordNeverExpires } "$AccountAuditDir\NonExpiringPasswords.txt"
Execute-Command { Get-ADUser -Filter "Enabled -eq \$true -and PasswordLastSet -lt \$PwdDate" -Properties PasswordLastSet | Select-Object Name, SamAccountName, PasswordLastSet } "$AccountAuditDir\OldPasswords.txt"
Execute-Command { Get-ADComputer -Filter "LastLogonDate -lt \$InactiveDate" -Properties LastLogonDate | Select-Object Name, DNSHostName, LastLogonDate } "$AccountAuditDir\InactiveComputers.txt"
Execute-Command { Get-ADComputer -Filter 'OperatingSystem -like "*Windows 7*" -or OperatingSystem -like "*Windows Server 2008*"' -Properties OperatingSystem | Select-Object Name, OperatingSystem } "$AccountAuditDir\OutdatedOSComputers.txt"
Execute-Command { Get-ADUser -Filter * -Properties * | Export-Csv -Path "$AccountAuditDir\ADUsers.csv" -NoTypeInformation } "$AccountAuditDir\ADUsersExport.txt"
Execute-Command { Get-ADGroup -Filter * | Export-Csv -Path "$AccountAuditDir\ADGroups.csv" -NoTypeInformation } "$AccountAuditDir\ADGroupsExport.txt"
Execute-Command { Get-ADServiceAccount -Filter * } "$AccountAuditDir\ADServiceAccounts.txt"
Execute-Command { Get-ADServiceAccount -Filter {ObjectClass -eq "msDS-GroupManagedServiceAccount"} | Export-Csv -Path "$AccountAuditDir\gMSAs.csv" -NoTypeInformation } "$AccountAuditDir\gMSAsExport.txt"

# Advanced Security Checks
Execute-Command { auditpol /get /category:* } "$AdvSecurityDir\DCAuditPolicy.txt"
Execute-Command { Get-ADUser -Filter 'AdminCount -eq 1' -Properties AdminCount | Select-Object Name, SamAccountName, DistinguishedName } "$AdvSecurityDir\AdminCountUsers.txt"
Execute-Command { Get-ADUser -Filter 'TrustedForDelegation -eq \$true' -Properties TrustedForDelegation | Select-Object Name, SamAccountName } "$AdvSecurityDir\KerberosDelegationUsers.txt"
Execute-Command { Get-ADComputer -Filter 'TrustedForDelegation -eq \$true' -Properties TrustedForDelegation | Select-Object Name, DNSHostName } "$AdvSecurityDir\KerberosDelegationComputers.txt"
Execute-Command { Get-ADUser -Filter 'SIDHistory -like "*"' -Properties SIDHistory | Select-Object Name, SamAccountName, SIDHistory } "$AdvSecurityDir\SIDHistoryUsers.txt"
Execute-Command { dcdiag /a } "$AdvSecurityDir\DCHealth.txt"
Execute-Command { reg query "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" } "$AdvSecurityDir\NTDSParameters.txt"

# Group Policy Auditing
Execute-Command { Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime } "$GPODir\GPOs.txt"
Execute-Command { Backup-GPO -All -Path "$GPODir\GPO_Backup" } "$GPODir\GPOBackupLog.txt"
Execute-Command { Get-GPOReport -All -ReportType Html -Path "$GPODir\GPOs.html" } "$GPODir\GPOHtmlExportLog.txt"

# System Time and Services
Execute-Command { w32tm /query /configuration } "$SystemInfoDir\TimeConfig.txt"
Execute-Command { w32tm /query /status } "$SystemInfoDir\TimeStatus.txt"
Execute-Command { Get-Service -ErrorAction SilentlyContinue | Select-Object DisplayName, Name, Status, StartType | Export-Csv -Path "$SystemInfoDir\Services.csv" -NoTypeInformation -Encoding UTF8 } "$SystemInfoDir\ServicesExportLog.txt"
