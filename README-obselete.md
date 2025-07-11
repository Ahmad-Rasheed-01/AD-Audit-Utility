# Active Directory Security Assessment Utility

A comprehensive PowerShell script for auditing Active Directory environments and identifying potential security vulnerabilities.

## Overview

This tool performs an automated security assessment of Active Directory domains, collecting critical configuration data and generating organized reports to help identify security gaps, compliance issues, and potential attack vectors.

## Features

### 🔍 **Comprehensive Security Auditing**
- **Forest & Domain Analysis**: Complete domain structure, trust relationships, and FSMO roles
- **Password Policy Assessment**: Default and fine-grained password policies evaluation
- **Privileged Account Auditing**: Analysis of high-privilege groups and accounts
- **Account Security Review**: Inactive accounts, service accounts, and password hygiene
- **Advanced Security Checks**: Kerberos delegation, SID history, and AdminCount analysis
- **Group Policy Auditing**: GPO analysis with backup and HTML reporting
- **System Configuration**: Domain controller health and time synchronization

### 📊 **Organized Output Structure**
Results are automatically organized into categorized directories:
```
ADResults_yyyyMMdd_HHmmss/
├── AuditResults/          # Main audit logs and script execution log
├── ForestDomain/          # Forest and domain information
├── SecurityPolicies/      # Password and account policies
├── PrivilegedGroups/      # High-privilege group memberships
├── AccountAudit/          # User and computer account analysis
├── AdvancedSecurity/      # Advanced security configurations
├── GPO/                   # Group Policy Objects and backups
└── SystemInfo/            # System and network configuration
```

## Prerequisites

- **Operating System**: Windows Server or Windows 10/11 with RSAT
- **PowerShell**: Version 5.1 or later
- **Modules Required**: ActiveDirectory PowerShell module
- **Permissions**: Domain Admin or equivalent privileges
- **Network**: Connectivity to domain controllers

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/AD-Assessment-Utility.git
   cd AD-Assessment-Utility
   ```

2. **Install Active Directory module** (if not already installed):
   ```powershell
   # On Windows Server
   Install-WindowsFeature -Name RSAT-AD-PowerShell
   
   # On Windows 10/11
   Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
   ```

## Usage

### Basic Execution
```powershell
# Run as Administrator
.\ADScript.ps1
```

### What the Script Does
1. **Validates Prerequisites**: Checks for required modules and permissions
2. **Creates Output Structure**: Generates timestamped directories for organized results
3. **Performs Security Assessment**: Executes comprehensive AD security checks
4. **Generates Reports**: Creates detailed reports in multiple formats (TXT, CSV, HTML)
5. **Logs Activities**: Maintains detailed execution logs for troubleshooting

## Output Reports

### 🏢 **Forest & Domain Information**
- Domain controller inventory and health status
- FSMO role assignments and forest/domain details
- Organizational unit structure and trust relationships

### 🔐 **Security Policies**
- Default domain password policy analysis
- Fine-grained password policy configurations
- Account lockout and security settings

### 👥 **Privileged Groups Analysis**
- Domain Admins, Enterprise Admins, Schema Admins membership
- Built-in Administrators group analysis
- Recursive group membership resolution

### 👤 **Account Security Assessment**
- Service account identification and analysis
- Inactive user and computer accounts (90+ days)
- Accounts with non-expiring passwords
- Outdated operating system inventory

### 🛡️ **Advanced Security Checks**
- Audit policy configuration analysis
- AdminCount attribute analysis
- Kerberos delegation configurations
- SID history analysis for potential security risks
- Domain controller health diagnostics

### 📋 **Group Policy Analysis**
- Complete GPO inventory with status and timestamps
- Automated GPO backup creation
- HTML-formatted GPO reports for detailed analysis

## Security Considerations

⚠️ **Important Security Notes**:
- This script requires elevated privileges and should only be run by authorized personnel
- Output files may contain sensitive information - secure storage and handling required
- Review and sanitize reports before sharing outside the security team
- Consider running during maintenance windows to minimize performance impact

## Troubleshooting

### Common Issues

**"Access Denied" Errors**:
- Ensure running as Administrator
- Verify domain admin or equivalent privileges
- Check network connectivity to domain controllers

**"Module Not Found" Errors**:
- Install Active Directory PowerShell module
- Verify RSAT tools installation

**Performance Issues**:
- Large environments may require extended execution time
- Consider running during off-peak hours
- Monitor domain controller performance during execution

### Log Analysis
Check the execution log for detailed error information:
```
ADResults_[timestamp]/AuditResults/ScriptLog.txt
```

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for legitimate security assessment purposes only. Users are responsible for:
- Obtaining proper authorization before running assessments
- Complying with organizational policies and legal requirements
- Securing and properly handling sensitive output data

## Support

For issues, questions, or feature requests, please open an issue in the GitHub repository.

---

**Version**: 1.0  
**Last Updated**: 2024  
**Compatibility**: Windows Server 2012+ / Windows 10+