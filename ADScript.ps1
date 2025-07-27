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
#
#AUTHOR
#    Ahmad Rasheed
#
#VERSION
#    1.0.2
#
#PREREQUISITES
#    - Must be run as Administrator
#    - Active Directory PowerShell module (RSAT) recommended for full functionality
#    - Windows Active Directory environment
#    - Sufficient permissions to read AD objects and system files
#
#NOTES
#    - This script is READ-ONLY and does not modify any AD or system configurations
#    - Some commands may not be available depending on the Windows version
#    - For updates, visit: https://github.com/Ahmad-Rasheed-01/AD-Audit-Utility
#
#OPERATIONAL INSTRUCTIONS
#    a) Scrutinize the contents of the script to ensure that it does not contain
#       any statements, commands or any other code that might negatively influence
#       the environment(s) in either a security or operational way.
#    b) Test the script on the test environment to ensure proper functionality.
#    c) The final responsibility for executing this script lies with the executor.
#    d) It is advised to execute the script during off-peak hours.

# Color definitions for PowerShell
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    switch ($Color) {
        "Red" { Write-Host $Message -ForegroundColor Red }
        "Green" { Write-Host $Message -ForegroundColor Green }
        "Yellow" { Write-Host $Message -ForegroundColor Yellow }
        "Cyan" { Write-Host $Message -ForegroundColor Cyan }
        "Blue" { Write-Host $Message -ForegroundColor Blue }
        "Magenta" { Write-Host $Message -ForegroundColor Magenta }
        "White" { Write-Host $Message -ForegroundColor White }
        default { Write-Host $Message }
    }
}

# Display banner
Write-ColorOutput "" "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "     █████╗ ██████╗      █████╗ ██╗   ██╗██████╗ ██╗████████╗    ██╗   ██╗████████╗██╗██╗     ██╗████████╗██╗   ██╗" "White"
Write-ColorOutput "    ██╔══██╗██╔══██╗    ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝    ██║   ██║╚══██╔══╝██║██║     ██║╚══██╔══╝╚██╗ ██╔╝" "White"
Write-ColorOutput "    ███████║██║  ██║    ███████║██║   ██║██║  ██║██║   ██║       ██║   ██║   ██║   ██║██║     ██║   ██║    ╚████╔╝ " "White"
Write-ColorOutput "    ██╔══██║██║  ██║    ██╔══██║██║   ██║██║  ██║██║   ██║       ██║   ██║   ██║   ██║██║     ██║   ██║     ╚██╔╝  " "White"
Write-ColorOutput "    ██║  ██║██████╔╝    ██║  ██║╚██████╔╝██████╔╝██║   ██║       ╚██████╔╝   ██║   ██║███████╗██║   ██║      ██║   " "White"
Write-ColorOutput "    ╚═╝  ╚═╝╚═════╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝        ╚═════╝    ╚═╝   ╚═╝╚══════╝╚═╝   ╚═╝      ╚═╝   " "White"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "     Platform: Windows Active Directory                                                                      " "White"
Write-ColorOutput "     Version: 1.0.2                                                                                 " "White"
Write-ColorOutput "     For Updates Please Visit: https://github.com/Ahmad-Rasheed-01/AD-Audit-Utility          " "White"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "═══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "" "White"
Write-Host

# Function to check if running as Administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if script is running as Administrator
if (-not (Test-Administrator)) {
    Write-ColorOutput "This script must be run as Administrator." "Red"
    Write-ColorOutput "Please restart PowerShell as Administrator and try again." "Yellow"
    Read-Host "Press Enter to exit"
    exit 1
}

# Check if Active Directory module is available
$ADModuleAvailable = $true
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-ColorOutput "✓ Active Directory module loaded successfully" "Green"
} catch {
    $ADModuleAvailable = $false
    Write-ColorOutput "✗ Active Directory module not found or failed to load" "Red"
    Write-ColorOutput "Please install RSAT (Remote Server Administration Tools) for full functionality." "Yellow"
    Write-ColorOutput "" "White"
    Write-ColorOutput "Note: Without RSAT, only system information will be collected." "Cyan"
    Write-ColorOutput "Active Directory-specific commands will be skipped." "Cyan"
    Write-ColorOutput "" "White"
    
    do {
        $response = Read-Host "Do you want to continue without RSAT? (Y/N)"
        $response = $response.ToUpper()
    } while ($response -ne "Y" -and $response -ne "N")
    
    if ($response -eq "N") {
        Write-ColorOutput "Collection cancelled by user. Please install RSAT and try again." "Yellow"
        Read-Host "Press Enter to exit"
        exit 0
    }
    
    Write-ColorOutput "⚠ Continuing without Active Directory module - limited functionality" "Yellow"
}

Write-Host
Write-ColorOutput "Obtaining system hostname, domain, and current date-time..." "Cyan"
$hostname = $env:COMPUTERNAME
$domain = (Get-WmiObject Win32_ComputerSystem).Domain
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
# Create the folder name and directory
$folder_name = "ADResults_${hostname}_${domain}_${timestamp}"
Write-ColorOutput "Creating folder: $folder_name" "Cyan"
$BasePath = Join-Path $PSScriptRoot $folder_name
$ReportPath = Join-Path $BasePath "AuditResults"
$GPOReportPath = Join-Path $BasePath "GPOReports"
$ForestDomainDir = Join-Path $BasePath "ForestDomain"
$SecurityPoliciesDir = Join-Path $BasePath "SecurityPolicies"
$PrivGroupsDir = Join-Path $BasePath "PrivilegedGroups"
$AccountAuditDir = Join-Path $BasePath "AccountAudit"
$AdvSecurityDir = Join-Path $BasePath "AdvancedSecurity"
$GPODir = Join-Path $BasePath "GPO"
$SystemInfoDir = Join-Path $BasePath "SystemInfo"
$LogFile = Join-Path $BasePath "ScriptLog.log"

# Create directories
$dirs = @($BasePath, $ReportPath, $GPOReportPath, $ForestDomainDir, $SecurityPoliciesDir, $PrivGroupsDir, $AccountAuditDir, $AdvSecurityDir, $GPODir, $SystemInfoDir)
foreach ($dir in $dirs) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}
Write-ColorOutput "DONE." "Green"

# Initialize log file and start time
$startTime = Get-Date
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
"$timestamp - [INFO] AD Audit Script started - Version 1.0.2" | Out-File -FilePath $LogFile -Encoding UTF8
"$timestamp - [INFO] Output folder: $folder_name" | Out-File -FilePath $LogFile -Append -Encoding UTF8
"$timestamp - [INFO] RSAT Available: $ADModuleAvailable" | Out-File -FilePath $LogFile -Append -Encoding UTF8
Write-Host

# Logging function with colors
function Log-Message {
    param (
        [string]$message,
        [string]$level = "INFO"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - [$level] $message"
    $logEntry | Out-File -FilePath $LogFile -Append
    
    switch ($level) {
        "SUCCESS" { Write-ColorOutput "✓ $message" "Green" }
        "ERROR" { Write-ColorOutput "✗ $message" "Red" }
        "WARNING" { Write-ColorOutput "⚠ $message" "Yellow" }
        "INFO" { Write-ColorOutput "ℹ $message" "Cyan" }
        default { Write-ColorOutput "$message" "White" }
    }
}

# Command execution with error handling and progress
function Execute-Command {
    param (
        [scriptblock]$command,
        [string]$outputFile,
        [string]$description = "Executing command",
        [bool]$requiresAD = $false
    )
    
    # Skip AD commands if module is not available
    if ($requiresAD -and -not $ADModuleAvailable) {
        Write-ColorOutput "$description... " "Yellow"
        "Command skipped: AD module not available" | Out-File -FilePath $outputFile -Encoding UTF8
        Log-Message "Skipped: $description - AD module not available" "WARNING"
        Write-Host
        return
    }
    
    try {
        Write-ColorOutput "$description..." "Cyan"
        & $command | Out-File -FilePath $outputFile -Encoding UTF8
        Log-Message "Successfully executed: $description" "SUCCESS"
        Write-ColorOutput "DONE." "Green"
    } catch {
        Log-Message "Failed to execute: $description - $_" "ERROR"
        Write-ColorOutput "FAILED: $_" "Red"
    }
    Write-Host
}

# Host and system info
Write-ColorOutput "Collecting host and system information..." "Yellow"
Execute-Command { hostname } "$SystemInfoDir\Hostname.txt" "Collecting hostname"
Execute-Command { ipconfig /all } "$SystemInfoDir\IPConfig.txt" "Collecting IP configuration"
Execute-Command { Get-WmiObject Win32_ComputerSystem | Select-Object Domain, Name, Manufacturer, Model | Format-List } "$SystemInfoDir\SystemSummary.txt" "Collecting system summary"
Execute-Command { Get-WmiObject Win32_OperatingSystem | Format-List } "$SystemInfoDir\OperatingSystem.txt" "Collecting operating system details"
Execute-Command { netstat -ano } "$SystemInfoDir\NetworkPorts.txt" "Collecting network port information"

# Forest and Domain Information
if ($ADModuleAvailable) {
    Write-ColorOutput "Collecting Active Directory forest and domain information..." "Yellow"
} else {
    Write-ColorOutput "Skipping Active Directory forest and domain information (AD module not available)..." "Yellow"
}
Execute-Command { Get-ADForest } "$ForestDomainDir\ForestInfo.txt" "Collecting forest information" -requiresAD $true
Execute-Command { Get-ADDomain } "$ForestDomainDir\DomainInfo.txt" "Collecting domain information" -requiresAD $true
Execute-Command { Get-ADDomainController -Filter * } "$ForestDomainDir\DomainControllers.txt" "Collecting domain controllers" -requiresAD $true
Execute-Command { netdom query fsmo } "$ForestDomainDir\FSMORoles.txt" "Collecting FSMO roles" -requiresAD $true
Execute-Command { Get-ADOrganizationalUnit -Filter * | Select-Object Name, DistinguishedName } "$ForestDomainDir\OrganizationalUnits.txt" "Collecting organizational units" -requiresAD $true
Execute-Command { Get-ADTrust -Filter * } "$ForestDomainDir\TrustRelationships.txt" "Collecting trust relationships" -requiresAD $true
Execute-Command { Get-ADDomainController -Filter * | Select-Object Name, IPv4Address, OperatingSystem, Site, IsGlobalCatalog, IsReadOnly | Export-Csv -Path "$ForestDomainDir\DC_List.csv" -NoTypeInformation } "$ForestDomainDir\DCListExport.txt" "Exporting domain controller list" -requiresAD $true
Execute-Command { Get-ADDomain | Select-Object InfrastructureMaster, PDCEmulator, RIDMaster } "$ForestDomainDir\DomainRoles.txt" "Collecting domain roles" -requiresAD $true
Execute-Command { Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster } "$ForestDomainDir\ForestRoles.txt" "Collecting forest roles" -requiresAD $true

# Password and Security Policies
if ($ADModuleAvailable) {
    Write-ColorOutput "Collecting password and security policies..." "Yellow"
} else {
    Write-ColorOutput "Skipping password and security policies (AD module not available)..." "Yellow"
}
Execute-Command { Get-ADDefaultDomainPasswordPolicy } "$SecurityPoliciesDir\DefaultDomainPasswordPolicy.txt" "Collecting default domain password policy" -requiresAD $true
Execute-Command { Get-ADFineGrainedPasswordPolicy -Filter * } "$SecurityPoliciesDir\FineGrainedPasswordPolicies.txt" "Collecting fine-grained password policies" -requiresAD $true
Execute-Command { net accounts /domain } "$SecurityPoliciesDir\AccountLockoutPolicy.txt" "Collecting account lockout policy" -requiresAD $true
Execute-Command { Get-ADDefaultDomainPasswordPolicy | Format-List } "$SecurityPoliciesDir\DefaultDomainPasswordPolicy_Formatted.txt" "Formatting default domain password policy" -requiresAD $true
Execute-Command { Get-ADFineGrainedPasswordPolicy -Filter * | Format-List } "$SecurityPoliciesDir\FineGrainedPasswordPolicies_Formatted.txt" "Formatting fine-grained password policies" -requiresAD $true
Execute-Command { net accounts /domain } "$SecurityPoliciesDir\AccountLockoutPolicy_Formatted.txt" "Formatting account lockout policy" -requiresAD $true

# Privileged Group Auditing
if ($ADModuleAvailable) {
    Write-ColorOutput "Auditing privileged groups..." "Yellow"
} else {
    Write-ColorOutput "Skipping privileged group auditing (AD module not available)..." "Yellow"
}
Execute-Command { Get-ADGroupMember -Identity 'Domain Admins' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\DomainAdmins.txt" "Collecting Domain Admins members" -requiresAD $true
Execute-Command { Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\EnterpriseAdmins.txt" "Collecting Enterprise Admins members" -requiresAD $true
Execute-Command { Get-ADGroupMember -Identity 'Schema Admins' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\SchemaAdmins.txt" "Collecting Schema Admins members" -requiresAD $true
Execute-Command { Get-ADGroupMember -Identity 'Administrators' -Recursive | Select-Object Name, SamAccountName, DistinguishedName } "$PrivGroupsDir\Administrators.txt" "Collecting Administrators members" -requiresAD $true

# Account Auditing
if ($ADModuleAvailable) {
    Write-ColorOutput "Performing account auditing..." "Yellow"
} else {
    Write-ColorOutput "Skipping account auditing (AD module not available)..." "Yellow"
}
$InactiveDate = (Get-Date).AddDays(-90)
$PwdDate = (Get-Date).AddDays(-90)
Execute-Command { Get-ADUser -Filter 'Name -like "svc*"' -Properties Name, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires | Select-Object Name, Enabled, LastLogonDate, PasswordLastSet, PasswordNeverExpires } "$AccountAuditDir\ServiceAccounts.txt" "Collecting service accounts" -requiresAD $true
Execute-Command { Get-ADUser -Filter "Enabled -eq \$true -and LastLogonDate -lt \$InactiveDate" -Properties LastLogonDate | Select-Object Name, SamAccountName, LastLogonDate } "$AccountAuditDir\InactiveUsers.txt" "Collecting inactive users" -requiresAD $true
Execute-Command { Get-ADUser -Filter "Enabled -eq \$true -and PasswordNeverExpires -eq \$true" -Properties PasswordNeverExpires | Select-Object Name, SamAccountName, PasswordNeverExpires } "$AccountAuditDir\NonExpiringPasswords.txt" "Collecting accounts with non-expiring passwords" -requiresAD $true
Execute-Command { Get-ADUser -Filter "Enabled -eq \$true -and PasswordLastSet -lt \$PwdDate" -Properties PasswordLastSet | Select-Object Name, SamAccountName, PasswordLastSet } "$AccountAuditDir\OldPasswords.txt" "Collecting accounts with old passwords" -requiresAD $true
Execute-Command { Get-ADComputer -Filter "LastLogonDate -lt \$InactiveDate" -Properties LastLogonDate | Select-Object Name, DNSHostName, LastLogonDate } "$AccountAuditDir\InactiveComputers.txt" "Collecting inactive computers" -requiresAD $true
Execute-Command { Get-ADComputer -Filter 'OperatingSystem -like "*Windows 7*" -or OperatingSystem -like "*Windows Server 2008*"' -Properties OperatingSystem | Select-Object Name, OperatingSystem } "$AccountAuditDir\OutdatedOSComputers.txt" "Collecting computers with outdated OS" -requiresAD $true
Execute-Command { Get-ADUser -Filter * -Properties * | Export-Csv -Path "$AccountAuditDir\ADUsers.csv" -NoTypeInformation } "$AccountAuditDir\ADUsersExport.txt" "Exporting all AD users" -requiresAD $true
Execute-Command { Get-ADGroup -Filter * | Export-Csv -Path "$AccountAuditDir\ADGroups.csv" -NoTypeInformation } "$AccountAuditDir\ADGroupsExport.txt" "Exporting all AD groups" -requiresAD $true
Execute-Command { Get-ADServiceAccount -Filter * } "$AccountAuditDir\ADServiceAccounts.txt" "Collecting AD service accounts" -requiresAD $true
Execute-Command { Get-ADServiceAccount -Filter {ObjectClass -eq "msDS-GroupManagedServiceAccount"} | Export-Csv -Path "$AccountAuditDir\gMSAs.csv" -NoTypeInformation } "$AccountAuditDir\gMSAsExport.txt" "Exporting group managed service accounts" -requiresAD $true

# Advanced Security Checks
if ($ADModuleAvailable) {
    Write-ColorOutput "Performing advanced security checks..." "Yellow"
} else {
    Write-ColorOutput "Skipping advanced security checks (AD module not available)..." "Yellow"
}
Execute-Command { auditpol /get /category:* } "$AdvSecurityDir\DCAuditPolicy.txt" "Collecting domain controller audit policy"
Execute-Command { Get-ADUser -Filter 'AdminCount -eq 1' -Properties AdminCount | Select-Object Name, SamAccountName, DistinguishedName } "$AdvSecurityDir\AdminCountUsers.txt" "Collecting users with AdminCount=1" -requiresAD $true
Execute-Command { Get-ADUser -Filter 'TrustedForDelegation -eq \$true' -Properties TrustedForDelegation | Select-Object Name, SamAccountName } "$AdvSecurityDir\KerberosDelegationUsers.txt" "Collecting users trusted for delegation" -requiresAD $true
Execute-Command { Get-ADComputer -Filter 'TrustedForDelegation -eq \$true' -Properties TrustedForDelegation | Select-Object Name, DNSHostName } "$AdvSecurityDir\KerberosDelegationComputers.txt" "Collecting computers trusted for delegation" -requiresAD $true
Execute-Command { Get-ADUser -Filter 'SIDHistory -like "*"' -Properties SIDHistory | Select-Object Name, SamAccountName, SIDHistory } "$AdvSecurityDir\SIDHistoryUsers.txt" "Collecting users with SID history" -requiresAD $true
Execute-Command { dcdiag /a } "$AdvSecurityDir\DCHealth.txt" "Running domain controller diagnostics" -requiresAD $true
Execute-Command { reg query "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" } "$AdvSecurityDir\NTDSParameters.txt" "Collecting NTDS parameters" -requiresAD $true

# Group Policy Auditing
if ($ADModuleAvailable) {
    Write-ColorOutput "Auditing Group Policy Objects..." "Yellow"
} else {
    Write-ColorOutput "Skipping Group Policy auditing (AD module not available)..." "Yellow"
}
Execute-Command { Get-GPO -All | Select-Object DisplayName, GpoStatus, CreationTime, ModificationTime } "$GPODir\GPOs.txt" "Collecting GPO information" -requiresAD $true
Execute-Command { Backup-GPO -All -Path "$GPODir\GPO_Backup" } "$GPODir\GPOBackupLog.txt" "Creating GPO backup" -requiresAD $true
Execute-Command { Get-GPOReport -All -ReportType Html -Path "$GPODir\GPOs.html" } "$GPODir\GPOHtmlExportLog.txt" "Generating GPO HTML report" -requiresAD $true

# System Time and Services
Write-ColorOutput "Collecting system time and services information..." "Yellow"
Execute-Command { w32tm /query /configuration } "$SystemInfoDir\TimeConfig.txt" "Collecting time configuration"
Execute-Command { w32tm /query /status } "$SystemInfoDir\TimeStatus.txt" "Collecting time synchronization status"
# Execute-Command { Get-Service -ErrorAction SilentlyContinue | Select-Object DisplayName, Name, Status, StartType | Export-Csv -Path "$SystemInfoDir\Services.csv" -NoTypeInformation -Encoding UTF8 } "$SystemInfoDir\ServicesExportLog.txt" "Exporting services information"
Execute-Command { Get-Service -ErrorAction SilentlyContinue | Select-Object * | Export-Csv -Path "$SystemInfoDir\Services.csv" -NoTypeInformation -Encoding UTF8 } "$SystemInfoDir\ServicesExportLog.txt" "Exporting services information"
# Create completion summary
Write-Host
Write-ColorOutput "Creating audit completion summary..." "Cyan"
Log-Message "Creating audit completion summary" "INFO"
$completionTime = Get-Date

# Build collected information list based on what was actually collected
$collectedInfo = @()
$collectedInfo += "- Host and System Information"
$collectedInfo += "- System Time and Services"

if ($ADModuleAvailable) {
    $collectedInfo += "- Active Directory Forest and Domain Details"
    $collectedInfo += "- Password and Security Policies"
    $collectedInfo += "- Privileged Group Memberships"
    $collectedInfo += "- Account Audit (Users, Computers, Service Accounts)"
    $collectedInfo += "- Advanced Security Configurations"
    $collectedInfo += "- Group Policy Objects and Settings"
} else {
    $collectedInfo += "- Limited system audit (RSAT not available)"
}

$collectedInfoText = $collectedInfo -join "`n"

$auditSummary = @"
Active Directory Audit Completion Summary
========================================
Audit Started: $((Get-Date).ToString())
Hostname: $hostname
Domain: $domain
Output Folder: $folder_name
RSAT Available: $ADModuleAvailable

Collected Information:
$collectedInfoText

All audit results have been saved to: $BasePath
Log file location: $LogFile

Audit completed successfully at: $completionTime
"@

$auditSummary | Out-File -FilePath "$BasePath\AuditSummary.txt" -Encoding UTF8
Log-Message "Audit summary created successfully" "SUCCESS"
Write-ColorOutput "DONE." "Green"
Write-Host

# Create archive of the audit results
Write-ColorOutput "Creating archive of audit results..." "Cyan"
Log-Message "Creating ZIP archive of audit results" "INFO"
$archivePath = "$PSScriptRoot\$folder_name.zip"
$archiveCreated = $false

# Check if Compress-Archive is available (PowerShell 5.0+)
if (Get-Command "Compress-Archive" -ErrorAction SilentlyContinue) {
    try {
        Compress-Archive -Path $BasePath -DestinationPath $archivePath -Force
        Log-Message "Archive created successfully: $archivePath" "SUCCESS"
        Write-ColorOutput "DONE." "Green"
        $archiveCreated = $true
    } catch {
        Log-Message "Failed to create archive using Compress-Archive: $_" "ERROR"
        Write-ColorOutput "FAILED: $_" "Red"
    }
} else {
    Log-Message "Compress-Archive cmdlet not available (requires PowerShell 5.0+)" "WARNING"
    Write-ColorOutput "SKIPPED: Compress-Archive not available (requires PowerShell 5.0+)" "Yellow"
}
Write-Host

# Final completion message
Write-ColorOutput "" "Cyan"
Write-ColorOutput "══════════════════════════════════════════════════════════════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "                                    🎉 Collection COMPLETED SUCCESSFULLY! 🎉                               " "Green"
Write-ColorOutput "                                                                                                            " "Cyan"
if ($ADModuleAvailable) {
    Write-ColorOutput "     All Active Directory audit results have been saved to:                                                 " "White"
} else {
    Write-ColorOutput "     System audit results have been saved to:                                                           " "White"
}
Write-ColorOutput "     📁 $folder_name                                                                                        " "Yellow"
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "     The audit folder contains organized reports in the following categories:                               " "White"
Write-ColorOutput "     • System Information                                                                                   " "White"
Write-ColorOutput "     • System Time and Services                                                                             " "White"
if ($ADModuleAvailable) {
    Write-ColorOutput "     • Forest and Domain Details                                                                           " "White"
    Write-ColorOutput "     • Security Policies                                                                                   " "White"
    Write-ColorOutput "     • Privileged Groups                                                                                   " "White"
    Write-ColorOutput "     • Account Audit Results                                                                               " "White"
    Write-ColorOutput "     • Advanced Security Checks                                                                            " "White"
    Write-ColorOutput "     • Group Policy Objects                                                                                " "White"
} else {
    Write-ColorOutput "     ⚠ AD-specific categories skipped (RSAT not available)                                             " "Yellow"
}
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "     📋 Summary report: AuditSummary.txt                                                                   " "Green"
Write-ColorOutput "     📝 Detailed log: ScriptLog.log                                                                       " "Green"
if ($archiveCreated) {
    Write-ColorOutput "     📦 Archive file: $folder_name.zip                                                                     " "Green"
}
Write-ColorOutput "                                                                                                            " "Cyan"
Write-ColorOutput "══════════════════════════════════════════════════════════════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput "" "White"

Log-Message "AD Audit Script completed successfully at $completionTime" "INFO"
Log-Message "Total execution time: $((New-TimeSpan -Start $startTime -End $completionTime).ToString())" "INFO"
Log-Message "All results saved to: $BasePath" "INFO"
Log-Message "Script execution finished" "INFO"

Write-ColorOutput "Press any key to exit..." "Yellow"
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
