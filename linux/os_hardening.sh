#!/bin/bash
# Linux OS Hardening Script - Run as root

LOG_FILE="/var/log/hardening.log"

# Function to log actions
log_action() {
    echo "$(date +'%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# User Management Hardening
harden_user_management() {
    log_action "Starting User Management Hardening"

    # Disable root SSH login
    sed -i 's/^PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
    systemctl restart sshd
    log_action "Disabled root SSH login"

    # Enforce strong password policies
    apt install -y libpam-pwquality
    echo "minlen = 12" >> /etc/security/pwquality.conf
    echo "dcredit = -1" >> /etc/security/pwquality.conf
    echo "ucredit = -1" >> /etc/security/pwquality.conf
    echo "ocredit = -1" >> /etc/security/pwquality.conf
    echo "lcredit = -1" >> /etc/security/pwquality.conf
    log_action "Enforced strong password policies"

    # Lock out users after failed login attempts
    echo "auth required pam_tally2.so deny=5 unlock_time=600" >> /etc/pam.d/common-auth
    log_action "Configured account lockout after 5 failed attempts"

    log_action "Completed User Management Hardening"
}

# Network Security Hardening
harden_network_security() {
    log_action "Starting Network Security Hardening"

    # Enable UFW and configure rules
    apt install -y ufw
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow ssh
    ufw enable
    log_action "Configured UFW firewall rules"

    # Disable ICMP (ping) requests
    echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
    sysctl -p
    log_action "Disabled ICMP ping requests"

    # Secure SSH settings
    sed -i 's/^#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
    sed -i 's/^#MaxAuthTries 6/MaxAuthTries 3/' /etc/ssh/sshd_config
    systemctl restart sshd
    log_action "Hardened SSH settings"

    log_action "Completed Network Security Hardening"
}

# System Configuration Hardening
harden_system_configurations() {
    log_action "Starting System Configuration Hardening"

    # Disable unnecessary services
    systemctl disable avahi-daemon.service --now
    systemctl disable cups.service --now
    log_action "Disabled Avahi and CUPS services"

    # Enable audit logging
    apt install -y auditd
    systemctl enable auditd --now
    auditctl -e 1
    log_action "Enabled audit logging"

    # Set password expiration policies
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs
    log_action "Configured password expiration policies"

    log_action "Completed System Configuration Hardening"
}

# Application Security Hardening
harden_application_security() {
    log_action "Starting Application Security Hardening"

    # Install security updates
    apt update && apt upgrade -y
    log_action "Installed security updates"

    # Enable AppArmor or SELinux
    if command -v apparmor_status &>/dev/null; then
        systemctl enable apparmor --now
        log_action "Enabled AppArmor"
    elif command -v getenforce &>/dev/null; then
        setenforce 1
        log_action "Enabled SELinux"
    else
        log_action "No AppArmor or SELinux found"
    fi

    log_action "Completed Application Security Hardening"
}

# Main Execution
log_action "Starting Linux OS Hardening Script"

harden_user_management
harden_network_security
harden_system_configurations
harden_application_security

log_action "Linux OS Hardening Script Completed"
echo "Hardening Completed. Check $LOG_FILE for details."
