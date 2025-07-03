# Security Policy

## Supported Versions

This Active Directory Security Assessment Utility is currently maintained and supported:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

### How to Report

We appreciate your efforts to responsibly disclose security vulnerabilities in this AD Assessment Utility. Please follow these guidelines:

#### 🔒 **Private Disclosure (Preferred)**

1. **GitHub Security Advisories**: Use GitHub's private vulnerability reporting feature
   - Go to the "Security" tab in this repository
   - Click "Report a vulnerability"
   - Fill out the advisory form with details

2. **GitHub Issues**: For non-sensitive security improvements
   - Create a private issue in this repository
   - Use the "Security" label

#### ⚠️ **What NOT to Do**

- **Do NOT** open public issues for security vulnerabilities
- **Do NOT** discuss vulnerabilities in public forums, chat rooms, or social media
- **Do NOT** attempt to exploit vulnerabilities beyond what's necessary for demonstration

### What to Include

When reporting a vulnerability, please provide:

- **Summary**: Brief description of the vulnerability
- **Impact**: Potential security impact on AD environments
- **Reproduction**: Step-by-step instructions to reproduce
- **Environment**: PowerShell version, Windows version, AD environment details
- **Evidence**: Screenshots, logs, or proof-of-concept (if safe to share)
- **Suggested Fix**: If you have ideas for remediation

## Response Timeline

We are committed to responding to security reports promptly:

| Stage | Timeline | Description |
|-------|----------|-------------|
| **Acknowledgment** | 48 hours | Confirm receipt of your report |
| **Initial Assessment** | 1 week | Preliminary evaluation of the issue |
| **Fix Development** | 2-4 weeks | Develop and test security patches |
| **Public Disclosure** | After fix | Public disclosure after fix is available |

## Security Measures

### Code Security

- **Code Reviews**: Security-focused peer reviews for all changes
- **PowerShell Best Practices**: Following PowerShell security guidelines
- **Input Validation**: Proper validation of user inputs and parameters
- **Error Handling**: Secure error handling without information disclosure

### Release Security

- **Testing**: Security testing before releases
- **Documentation**: Clear security documentation and warnings
- **Dependencies**: Minimal external dependencies to reduce attack surface

## Vulnerability Categories

### High Priority

- **Code Injection in PowerShell**
- **Privilege Escalation**
- **Credential Exposure**
- **Malicious Script Execution**

### Medium Priority

- **Information Disclosure**
- **Input Validation Issues**
- **Insecure File Operations**

### Lower Priority

- **Information Leakage in Logs**
- **Weak Error Handling**

## Security Best Practices for Users

### For System Administrators

#### Before Running the Assessment

- **Review the Script**: Always review the PowerShell script before execution
- **Test Environment**: Run in a test environment first if possible
- **Backup Considerations**: Ensure you have proper backups before running
- **Execution Policy**: Set appropriate PowerShell execution policy

#### Secure Usage

- **Least Privilege**: Run with minimum required privileges
- **Output Security**: Secure the output files containing sensitive AD information
- **Network Security**: Run from a secure, monitored system
- **Log Review**: Review execution logs for any anomalies

#### After Assessment

- **Secure Storage**: Store assessment results securely
- **Access Control**: Limit access to assessment reports
- **Data Retention**: Follow organizational data retention policies
- **Remediation**: Address identified security issues promptly

## Security Resources

### External Resources

- **PowerShell Security**: https://docs.microsoft.com/en-us/powershell/scripting/security/
- **Active Directory Security**: https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/
- **CVE Database**: https://cve.mitre.org/
- **Security Advisories**: https://github.com/advisories

## Scope

This security policy applies to:

- **In Scope**: This AD Assessment Utility repository and its PowerShell script
- **Out of Scope**: Third-party Active Directory environments
- **Out of Scope**: Social engineering attacks
- **Out of Scope**: Physical attacks

## Safe Harbor

We support responsible disclosure for security researchers who:

- Make a good faith effort to avoid privacy violations
- Do not access, modify, or delete data belonging to others
- Provide reasonable time for us to resolve issues before disclosure

---

**Last Updated**: December 2024
**Version**: 1.0

*This security policy may be updated as our security practices evolve.*