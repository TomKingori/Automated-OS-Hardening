# Automated OS Hardening

This project provides automated OS hardening scripts for both Windows and Linux to enhance system security by applying best practices.

## Features
- Disables unnecessary services  
- Enforces strong password policies  
- Secures SSH, RDP, and firewall settings  
- Enables audit logging and security modules (SELinux/AppArmor)  
- Installs critical security updates  

## How to Use

### Linux
1. Navigate to the script location:
   ```bash
   cd linux
   ```

2. Make the script executable:
   ```bash
   chmod +x os_hardening.sh
   ```

3. Run the script as root:
   ```bash
   sudo ./os_hardening.sh
   ```

### Windows
1. Open PowerShell as Administrator.

2. Navigate to the script directory:
   ```bash
   cd windows
   ```

3. Allow execution (if restricted):
   ```bash
   Set-ExecutionPolicy Unrestricted -Scope Process
   ```

4. Run the script:
   ```bash
   ./os_hardening.ps1
   ```

## Logs

- **Linux:** `/var/log/hardening.log`  
- **Windows:** `C:\HardeningLog.txt`  

## Security Note

These scripts modify critical security settings. Test in a non-production environment first.  
