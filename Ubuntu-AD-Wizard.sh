#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Color codes for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Function to print colored output
print_color() {
    printf "${!1}%s${NC}\n" "$2"
}

# Function to print section headers
print_section() {
    echo ""
    print_color "CYAN" "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
    printf "${CYAN}┃ %-69s ┃${NC}\n" "$1"
    print_color "CYAN" "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
    echo ""
}

# Function to print ASCII art banner
print_banner() {
    echo ""
    print_color "CYAN"   "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓"
    print_color "CYAN"   "┃                                                                 ┃"
    print_color "MAGENTA" "┃   ██╗   ██╗██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗       ┃"
    print_color "MAGENTA" "┃   ██║   ██║██╔══██╗██║   ██║████╗  ██║╚══██╔══╝██║   ██║       ┃"
    print_color "MAGENTA" "┃   ██║   ██║██████╔╝██║   ██║██╔██╗ ██║   ██║   ██║   ██║       ┃"
    print_color "MAGENTA" "┃   ██║   ██║██╔══██╗██║   ██║██║╚██╗██║   ██║   ██║   ██║       ┃"
    print_color "MAGENTA" "┃   ╚██████╔╝██████╔╝╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝       ┃"
    print_color "MAGENTA" "┃    ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝        ┃"
    print_color "CYAN"   "┃                                                                 ┃"
    print_color "YELLOW" "┃                   A C T I V E  D I R E C T O R Y               ┃"
    print_color "CYAN"   "┃                                                                 ┃"
    print_color "WHITE"  "┃                    W I Z A R D  S C R I P T                    ┃"
    print_color "CYAN"   "┃                                                                 ┃"
    print_color "GREEN"  "┃                       by: Yan Zhou                              ┃"
    print_color "CYAN"   "┃                                                                 ┃"
    print_color "CYAN"   "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛"
    echo ""
}

# Function to print progress bar
print_progress_bar() {
    local duration=$1
    local steps=20
    local sleep_time=$(echo "scale=4; $duration/$steps" | bc)
    
    echo -ne "${YELLOW}["
    for ((i=0; i<steps; i++)); do
        echo -ne "${GREEN}#"
        sleep "$sleep_time"
    done
    echo -ne "${YELLOW}] ${GREEN}Complete!${NC}\n"
}

# Function to install a package
install_package() {
    if ! dpkg -s "$1" >/dev/null 2>&1; then
        print_color "YELLOW" "Installing $1..."
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" || {
            print_color "RED" "Failed to install $1. Exiting."
            exit 1
        }
        print_progress_bar 2
    else
        print_color "GREEN" "$1 is already installed."
    fi
}

# Function to prompt for yes/no
prompt_yes_no() {
    while true; do
        read -p "$1 (y/n): " choice
        case "$choice" in 
            y|Y ) return 0;;
            n|N ) return 1;;
            * ) echo "Please answer y or n.";;
        esac
    done
}

# Function to backup a file
backup_file() {
    local file="$1"
    local backup="${file}.bak_$(date +%Y%m%d_%H%M%S)"
    if [[ -f "$file" ]]; then
        sudo cp "$file" "$backup"
        print_color "YELLOW" "Backed up $file to $backup"
    else
        print_color "YELLOW" "File $file does not exist, skipping backup."
    fi
}

# Function to backup important files
backup_files() {
    print_section "Backing Up Important Files"
        
    local backup_dir="/root/ad_join_backup_$(date +%Y%m%d_%H%M%S)"
    if [ -d "$backup_dir" ]; then
        print_color "YELLOW" "Backup directory already exists. Using a new name."
        backup_dir="${backup_dir}_$(date +%s)"
    fi
    sudo mkdir -p "$backup_dir"
    local files_to_backup=("/etc/krb5.conf" "/etc/sssd/sssd.conf" "/etc/nsswitch.conf" "/etc/pam.d/common-session" "/etc/sudoers")
    for file in "${files_to_backup[@]}"; do
        if [[ -f "$file" ]]; then
            sudo cp "$file" "$backup_dir/"
            print_color "GREEN" "✅ Backed up $file"
        fi
    done
    print_color "GREEN" "✅ Backups saved in $backup_dir"
    print_progress_bar 2
}

# Function to validate input
validate_input() {
    local input="$1"
    local type="$2"
    case "$type" in
        "username")
            [[ -z "$input" || "$input" =~ [[:space:]] ]] && return 1 || return 0
            ;;
        "password")
            [[ -z "$input" ]] && return 1 || return 0
            ;;
        "domain")
            [[ "$input" =~ ^([a-zA-Z0-9](([a-zA-Z0-9-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$ ]] && return 0 || return 1
            ;;
        "ip")
            [[ "$input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && return 0 || return 1
            ;;
    esac
}

# Function to log messages
log_message() {
    local message="$1"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $message" >> /var/log/domain_join.log
}

# Function to check if a package is installed
is_package_installed() {
    dpkg -s "$1" >/dev/null 2>&1
}

# Function to check if all required packages are installed
check_dependencies() {
    local dependencies=("realmd" "sssd" "sssd-tools" "libnss-sss" "libpam-sss" "adcli" "samba-common-bin" "oddjob" "oddjob-mkhomedir" "packagekit" "krb5-user")
    local missing_deps=()

    for package in "${dependencies[@]}"; do
        if ! is_package_installed "$package"; then
            missing_deps+=("$package")
        fi
    done

    if [ ${#missing_deps[@]} -eq 0 ]; then
        return 0
    else
        print_color "YELLOW" "The following dependencies are missing:"
        printf '%s\n' "${missing_deps[@]}"
        return 1
    fi
}

# Function to ensure a directory exists
ensure_directory_exists() {
    local dir_path="$1"
    if [ ! -d "$dir_path" ]; then
        print_color "YELLOW" "Directory $dir_path does not exist. Creating it now..."
        sudo mkdir -p "$dir_path"
        if [ $? -eq 0 ]; then
            print_color "GREEN" "✅ Directory $dir_path created successfully."
        else
            print_color "RED" "❌ Failed to create directory $dir_path. Please check permissions and try again."
            return 1
        fi
    fi
    return 0
}

# Function to configure Kerberos with permitted encryption types
configure_kerberos() {
    print_section "Configuring Kerberos"
    backup_file "/etc/krb5.conf"
    sudo tee /etc/krb5.conf > /dev/null <<EOT
[libdefaults]
    default_realm = ${domain_address^^}
    dns_lookup_realm = true
    dns_lookup_kdc = true
    ticket_lifetime = 24h
    renew_lifetime = 7d
    forwardable = true
    rdns = false
    default_ccache_name = FILE:/tmp/krb5cc_%{uid}
    default_tgs_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    default_tkt_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac
    permitted_enctypes = aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 rc4-hmac

[realms]
    ${domain_address^^} = {
        kdc = ${domain_address}
        admin_server = ${domain_address}
    }

[domain_realm]
    .${domain_address} = ${domain_address^^}
    ${domain_address} = ${domain_address^^}
EOT
    print_color "GREEN" "✅ Improved Kerberos configuration completed."
}

# Function to ensure SSSD directory exists
ensure_sssd_directory() {
    print_section "Checking SSSD Directory"
    if [ ! -d "/etc/sssd" ]; then
        print_color "YELLOW" "SSSD directory not found. Creating..."
        sudo mkdir -p /etc/sssd
        sudo chmod 711 /etc/sssd
    fi
    print_color "GREEN" "✅ SSSD directory checked/created."
}

# Function to configure SSSD
configure_sssd() {
    print_section "Configuring SSSD"
    
    ensure_directory_exists "/etc/sssd"

    sudo tee /etc/sssd/sssd.conf > /dev/null <<EOT
[sssd]
domains = $domain_address
config_file_version = 2
services = nss, pam, sudo, ssh

[domain/$domain_address]
default_shell = /bin/bash
krb5_store_password_if_offline = True
cache_credentials = True
krb5_realm = ${domain_address^^}
realmd_tags = manages-system joined-with-adcli
id_provider = ad
fallback_homedir = /home/%u@%d
ad_domain = $domain_address
use_fully_qualified_names = False
ldap_id_mapping = True
access_provider = ad
ldap_schema = ad
ldap_user_principal = nosuchattribute
ldap_user_name = sAMAccountName
ldap_group_name = sAMAccountName
ldap_force_upper_case_realm = True
enumerate = False
ldap_referrals = False
override_homedir = /home/%u@%d
default_shell = /bin/bash
EOT

    # Set correct permissions for sssd.conf
    sudo chmod 600 /etc/sssd/sssd.conf

    print_color "GREEN" "✅ SSSD configuration completed."

    # Verify the file was created and has correct permissions
    if [ -f "/etc/sssd/sssd.conf" ]; then
        local file_perms=$(stat -c "%a" /etc/sssd/sssd.conf)
        if [ "$file_perms" = "600" ]; then
            print_color "GREEN" "✅ SSSD configuration file created with correct permissions."
        else
            print_color "YELLOW" "⚠️ SSSD configuration file created, but permissions are not 600. Current permissions: $file_perms"
        fi
    else
        print_color "RED" "❌ Failed to create SSSD configuration file."
        return 1
    fi
}

# Function to configure PAM
configure_pam() {
    print_section "Configuring PAM"
    # Configure PAM for home directory creation
    if ! sudo pam-auth-update --enable mkhomedir; then
        print_color "RED" "Failed to update PAM configuration. Please check PAM settings manually."
        log_message "Failed to update PAM configuration"
    fi

    # Ensure pam_mkhomedir.so is in the common-session file
    if ! grep -q "pam_mkhomedir.so" /etc/pam.d/common-session; then
        sudo sed -i '/pam_unix.so/a session required pam_mkhomedir.so skel=/etc/skel/ umask=0022' /etc/pam.d/common-session
    fi
    
    print_color "GREEN" "✅ PAM configuration completed."
}

# Function to configure PAM
configure_pam() {
    print_section "Configuring PAM"
    
    sudo pam-auth-update --enable mkhomedir
    sudo pam-auth-update --enable sssd

    # Ensure SSSD is properly configured in common-auth
    if ! grep -q "pam_sss.so" /etc/pam.d/common-auth; then
        sudo sed -i '/^auth.*pam_unix.so/i auth        sufficient                  pam_sss.so use_first_pass' /etc/pam.d/common-auth
    fi

    print_color "GREEN" "✅ PAM configuration completed."
}

# Function to install GPO support packages
install_gpo_packages() {
    print_section "Installing GPO Support Packages"
    local gpo_packages=("adcli" "samba-common-bin" "sssd-tools" "libnss-sss" "libpam-sss" "krb5-user" "packagekit")
    for package in "${gpo_packages[@]}"; do
        install_package "$package"
    done
    print_color "GREEN" "✅ GPO support packages installed successfully."
}

# Function to configure GPO support
configure_gpo_support() {
    print_section "Configuring GPO Support"

    # Update SSSD configuration for GPO support
    sudo sed -i '/services = nss, pam/c\services = nss, pam, sudo, ssh' /etc/sssd/sssd.conf
    sudo sed -i '/\[domain\/.*\]/a ad_gpo_access_control = enforcing\ngpo_cache_timeout = 5\nldap_schema = ad\nad_gpo_map_remote_interactive = +gdm-welcome' /etc/sssd/sssd.conf

    # Configure PAM for GPO support
    sudo pam-auth-update --enable mkhomedir
    sudo pam-auth-update --enable sssd

    print_color "GREEN" "✅ GPO support configured successfully."
}

# Function to prompt for OU
prompt_for_ou() {
    print_section "Organizational Unit Specification"
    print_color "YELLOW" "Specify the OU where the computer account should be created."
    print_color "YELLOW" "Leave blank to use the default Computers container."
    print_color "YELLOW" "Format: OU=SubOU,OU=ParentOU,DC=domain,DC=com"
    while true; do
        read -p "Enter the OU DN (or press Enter for default): " ou_dn
        if [[ -z "$ou_dn" ]]; then
            print_color "GREEN" "Using default Computers container."
            return
        elif [[ "$ou_dn" =~ ^OU=.*,DC=.*$ ]]; then
            print_color "GREEN" "Using specified OU: $ou_dn"
            return
        else
            print_color "RED" "Invalid OU format. Please use the format OU=SubOU,OU=ParentOU,DC=domain,DC=com"
        fi
    done
}

# Function to configure NSSwitch
configure_nsswitch() {
    print_section "Configuring NSSwitch"
    local nsswitch_config="/etc/nsswitch.conf"  
    
    # Backup the original nsswitch.conf
    backup_file "$nsswitch_config"
    
    # Configure NSSwitch entries
    configure_nsswitch_entry() {
        local key="$1"
        local value="$2"
        if grep -q "^$key:" "$nsswitch_config"; then
            sudo sed -i "s/^$key:.*$/$key:     $value/" "$nsswitch_config"
        else
            echo "$key:     $value" | sudo tee -a "$nsswitch_config" > /dev/null
        fi
    }

    configure_nsswitch_entry "passwd" "compat systemd sss"
    configure_nsswitch_entry "group" "compat systemd sss"
    configure_nsswitch_entry "shadow" "compat sss"
    configure_nsswitch_entry "gshadow" "files"
    configure_nsswitch_entry "hosts" "files dns"
    configure_nsswitch_entry "networks" "files"
    configure_nsswitch_entry "protocols" "db files"
    configure_nsswitch_entry "services" "db files sss"
    configure_nsswitch_entry "ethers" "db files"
    configure_nsswitch_entry "rpc" "db files"
    configure_nsswitch_entry "netgroup" "nis sss"

    # Verify NSSwitch configuration
    if grep -q "passwd:.*sss" "$nsswitch_config" && 
       grep -q "group:.*sss" "$nsswitch_config" && 
       grep -q "shadow:.*sss" "$nsswitch_config" && 
       grep -q "netgroup:.*sss" "$nsswitch_config"; then
        print_color "GREEN" "✅ NSSwitch configuration completed and verified."
    else
        print_color "RED" "❌ NSSwitch configuration may be incorrect. Here's the current content of $nsswitch_config:"
        cat "$nsswitch_config"
        log_message "NSSwitch configuration may be incorrect"
        print_color "YELLOW" "Please check the above output and ensure 'sss' is present in passwd, group, shadow, and netgroup lines."
        
        if prompt_yes_no "Would you like to manually edit the NSSwitch configuration?"; then
            sudo nano "$nsswitch_config"
            print_color "YELLOW" "NSSwitch configuration has been manually edited. Please verify the changes."
        else
            print_color "YELLOW" "Skipping manual edit. Please review and update $nsswitch_config manually if needed."
        fi
    fi
    
    # Display the final NSSwitch configuration
    print_color "CYAN" "Final NSSwitch Configuration:"
    cat "$nsswitch_config"
    
    print_progress_bar 2
}

# Function to test user lookup
test_user_lookup() {
    print_section "Testing Domain User Lookup"
    read -p "Enter a domain username to test: " test_username

    print_color "YELLOW" "Verifying domain user..."
    if id "$test_username" &>/dev/null; then
        print_color "GREEN" "✅ Domain user '$test_username' verified successfully."
    else
        print_color "RED" "❌ Failed to verify domain user '$test_username'."
        if prompt_yes_no "Would you like to see detailed troubleshooting information?"; then
            advanced_troubleshoot_user_lookup "$test_username"
        else
            print_color "YELLOW" "Please ensure the username is correct and the domain join was successful."
        fi
    fi
}

# Function for advanced troubleshooting of user lookup issues
advanced_troubleshoot_user_lookup() {
    local test_username="$1"

    print_section "Advanced Troubleshooting"

    print_color "YELLOW" "1. Checking SSSD service status:"
    sudo systemctl status sssd

    print_color "YELLOW" "2. Verifying SSSD configuration:"
    sudo cat /etc/sssd/sssd.conf

    print_color "YELLOW" "3. Checking SSSD logs for errors:"
    sudo journalctl -u sssd -n 50 --no-pager

    print_color "YELLOW" "4. Testing AD connectivity:"
    ping -c 4 "$domain_address"

    print_color "YELLOW" "5. Verifying DNS resolution:"
    nslookup "$domain_address"

    print_color "YELLOW" "6. Checking Kerberos ticket:"
    klist

    print_color "YELLOW" "7. Attempting to get a new Kerberos ticket:"
    echo "$admin_password" | kinit "$admin_username"@"${domain_address^^}" 2>&1

    print_color "YELLOW" "8. Verifying domain join status:"
    realm list

    print_color "YELLOW" "9. Checking LDAP connection:"
    ldapsearch -H ldap://"$domain_address" -x -LLL -b "$(realm list | grep domain-name | awk '{print $2}' | sed 's/^/dc=/;s/\./,dc=/g')" "(sAMAccountName=$test_username)"

    print_color "YELLOW" "10. Clearing SSSD cache and restarting service:"
    sudo sss_cache -E
    sudo systemctl restart sssd

    print_color "YELLOW" "11. Retrying user lookup after cache clear:"
    sleep 5
    id "$test_username"

    print_color "GREEN" "Advanced troubleshooting completed. Please review the output above."
    print_color "YELLOW" "Common issues and solutions:"
    print_color "WHITE" "- If SSSD is not running or has errors, try reinstalling it: sudo apt-get install --reinstall sssd sssd-tools"
    print_color "WHITE" "- If there are connectivity issues, check your network settings and firewall rules"
    print_color "WHITE" "- If Kerberos tickets can't be obtained, verify the time synchronization between the client and domain controller"
    print_color "WHITE" "- If LDAP connection fails, ensure the necessary ports (389/636) are open and LDAP is enabled on the domain controller"
    print_color "WHITE" "- If the issue persists after clearing cache, try rebooting the system"
    print_color "WHITE" "- Verify that the user account exists in Active Directory and has the correct attributes"
    print_color "WHITE" "- Check if the user is in the correct OU that SSSD is configured to search"

    if prompt_yes_no "Would you like to attempt rejoining the domain?"; then
        rejoin_domain
    fi
}

# Function to rejoin the domain
rejoin_domain() {
    print_color "YELLOW" "Attempting to leave and rejoin the domain..."
    
    # Leave the domain
    sudo realm leave

    # Rejoin the domain
    join_command="echo \"$admin_password\" | sudo realm join --verbose --install=/ --user=\"$admin_username\""
    if [[ -n "$ou_dn" ]]; then
        join_command+=" --computer-ou=\"$ou_dn\""
    fi
    join_command+=" \"$domain_address\""

    if eval "$join_command"; then
        print_color "GREEN" "✅ Successfully rejoined the domain."
        # Restart SSSD and clear cache
        sudo systemctl restart sssd
        sudo sss_cache -E
        print_color "YELLOW" "SSSD restarted and cache cleared. Please try user lookup again."
        test_user_lookup
    else
        print_color "RED" "❌ Failed to rejoin the domain. Please check your domain settings and credentials."
    fi
}

# Function to configure sudo for domain users
configure_sudo_for_domain_users() {
    print_section "Configuring Sudo for Domain Users"
    
    # Add domain admins to sudoers
    echo "%domain\ admins ALL=(ALL) ALL" | sudo tee -a /etc/sudoers > /dev/null
    
    # Configure sudo to read from SSSD
    if ! grep -q "sudoers:.*sss" /etc/nsswitch.conf; then
        sudo sed -i '/^sudoers:/s/$/ sss/' /etc/nsswitch.conf
    fi
    
    print_color "GREEN" "✅ Sudo access configured for domain users."
}

# Function to cleanup on script interruption
cleanup() {
    print_color "YELLOW" "Script interrupted. Cleaning up..."
    # Add cleanup tasks here if necessary
    exit 1
}

# Set up trap for cleanup function
trap cleanup SIGINT SIGTERM

# Main script starts here
clear
print_banner

print_color "WHITE" "Welcome to the Domain Join Script!"
echo "This script will guide you through the process of joining your Ubuntu system to an Active Directory domain."
echo ""

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    print_color "RED" "❌ This script must be run as root. Please use sudo."
    exit 1
fi

# Check Ubuntu version
if ! grep -q "Ubuntu 2[2-9]" /etc/os-release; then
    print_color "RED" "❌ This script requires Ubuntu 22.04 or higher. Exiting."
    exit 1
fi

# Prompt to continue
if ! prompt_yes_no "Do you want to proceed?"; then
    print_color "YELLOW" "Script execution cancelled. Goodbye! 👋"
    exit 0
fi

# Check network connectivity
print_section "Checking Network Connectivity"
if ! ping -c 1 google.com &> /dev/null; then
    print_color "RED" "❌ No network connectivity. Please check your network settings and try again."
    exit 1
fi
print_color "GREEN" "✅ Network connectivity confirmed."
print_progress_bar 2

# Check and synchronize time
print_section "Checking Time Synchronization"
if ! timedatectl status | grep -q "NTP synchronized: yes"; then
    print_color "YELLOW" "NTP is not synchronized. Attempting to synchronize..."
    
    # Try using timedatectl first
    if sudo timedatectl set-ntp true; then
        sleep 5
        if timedatectl status | grep -q "NTP synchronized: yes"; then
            print_color "GREEN" "✅ Time synchronized successfully using timedatectl."
        else
            print_color "YELLOW" "timedatectl failed to synchronize. Trying ntpdate..."
            
            # If timedatectl fails, try using ntpdate
            if ! command -v ntpdate &> /dev/null; then
                print_color "YELLOW" "ntpdate not found. Installing..."
                sudo apt-get update && sudo apt-get install -y ntpdate
            fi
            
            if sudo ntpdate pool.ntp.org; then
                print_color "GREEN" "✅ Time synchronized successfully using ntpdate."
            else
                print_color "RED" "⚠️ Failed to synchronize time. This may cause issues with AD authentication."
                log_message "Failed to synchronize time using both timedatectl and ntpdate."
            fi
        fi
    else
        print_color "YELLOW" "timedatectl failed. Trying ntpdate..."
        
        # If timedatectl fails, try using ntpdate
        if ! command -v ntpdate &> /dev/null; then
            print_color "YELLOW" "ntpdate not found. Installing..."
            sudo apt-get update && sudo apt-get install -y ntpdate
        fi
        
        if sudo ntpdate pool.ntp.org; then
            print_color "GREEN" "✅ Time synchronized successfully using ntpdate."
        else
            print_color "RED" "⚠️ Failed to synchronize time. This may cause issues with AD authentication."
            log_message "Failed to synchronize time using both timedatectl and ntpdate."
        fi
    fi
else
    print_color "GREEN" "✅ Time is already synchronized."
fi
print_progress_bar 2

# Backup important files
backup_files

# Check and install dependencies if necessary
print_section "Checking Dependencies"
if check_dependencies; then
    print_color "GREEN" "✅ All required dependencies are already installed."
else
    print_color "YELLOW" "Some dependencies are missing. Installing now..."
    sudo apt-get update || {
        print_color "RED" "Failed to update package lists. Please check your internet connection and try again."
        exit 1
    }

    dependencies=("realmd" "sssd" "sssd-tools" "libnss-sss" "libpam-sss" "adcli" "samba-common-bin" "oddjob" "oddjob-mkhomedir" "packagekit" "krb5-user")
    for package in "${dependencies[@]}"; do
        install_package "$package"
    done
fi
print_progress_bar 2

# Prompt for domain information
print_section "Domain Information"
while true; do
    read -p "Enter the domain address (e.g., example.com): " domain_address
    if validate_input "$domain_address" "domain"; then
        break
    else
        print_color "RED" "Invalid domain address format. Please enter a valid domain (e.g., example.com)."
    fi
done

# Check DNS resolution
print_section "Checking DNS Resolution"
if ! nslookup "$domain_address" &> /dev/null; then
    print_color "RED" "❌ Unable to resolve domain $domain_address. Please check your DNS settings."
    exit 1
fi
print_color "GREEN" "✅ Domain DNS resolution successful."
print_progress_bar 2

# Prompt for DNS server configuration
if prompt_yes_no "Do you want to specify a DNS server address?"; then
    while true; do
        read -p "Enter the DNS server IP address: " dns_server
        if validate_input "$dns_server" "ip"; then
            print_section "Configuring DNS"
            # Update resolv.conf
            sudo tee /etc/resolv.conf > /dev/null <<EOT
nameserver $dns_server
search $domain_address
EOT
            # Update systemd-resolved configuration
            sudo tee /etc/systemd/resolved.conf > /dev/null <<EOT
[Resolve]
DNS=$dns_server
Domains=$domain_address
EOT
            sudo systemctl restart systemd-resolved
            print_color "GREEN" "✅ DNS configured to use specified server."
            break
        else
            print_color "RED" "Invalid IP address format. Please enter a valid IPv4 address."
        fi
    done
else
    print_color "YELLOW" "Skipping manual DNS configuration."
fi
print_progress_bar 2

# Configure firewall
print_section "Configuring Firewall"
if sudo ufw status | grep -q "Status: active"; then
    print_color "YELLOW" "Configuring firewall rules for AD..."
    sudo ufw allow proto tcp from any to any port 53,88,389,464,636,3268,3269,445
    sudo ufw allow proto udp from any to any port 53,88,464
    print_color "GREEN" "✅ Firewall rules added for AD communication."
else
    print_color "YELLOW" "Firewall is not active. No changes made."
fi
print_progress_bar 2

# Function to verify AD admin credentials
verify_ad_credentials() {
    print_section "Verifying AD Admin Credentials"
    print_color "YELLOW" "Attempting to verify AD admin credentials..."

    # Create a temporary Kerberos ticket cache
    local temp_krb5ccname=$(mktemp)
    export KRB5CCNAME="FILE:$temp_krb5ccname"

    # Attempt to get a Kerberos ticket
    if echo "$admin_password" | kinit "$admin_username"@"${domain_address^^}" 2>/dev/null; then
        print_color "GREEN" "✅ AD admin credentials verified successfully."
        kdestroy  # Clean up the Kerberos ticket
        unset KRB5CCNAME
        rm -f "$temp_krb5ccname"
        return 0
    else
        print_color "RED" "❌ Failed to verify AD admin credentials."
        print_color "YELLOW" "Please check the following:"
        print_color "YELLOW" "1. Admin username and password are correct"
        print_color "YELLOW" "2. Domain name is correct"
        print_color "YELLOW" "3. Network connectivity to the domain controller"
        print_color "YELLOW" "4. DNS resolution is working correctly"
        unset KRB5CCNAME
        rm -f "$temp_krb5ccname"
        return 1
    fi
}

# Prompt for admin credentials
print_section "Admin Credentials"
while true; do
    read -p "Enter the admin username: " admin_username
    if validate_input "$admin_username" "username"; then
        break
    else
        print_color "RED" "Invalid username. Username cannot be empty or contain spaces."
    fi
done

while true; do
    read -sp "Enter the password for $admin_username: " admin_password
    echo
    if validate_input "$admin_password" "password"; then
        break
    else
        print_color "RED" "Invalid password. Password cannot be empty."
    fi
done

# Verify AD admin credentials
if ! verify_ad_credentials; then
    print_color "RED" "Failed to verify AD admin credentials. Please check your inputs and try again."
    exit 1
fi

# Configure Kerberos
configure_kerberos

# Ensure SSSD directory exists
ensure_sssd_directory

# Prompt for OU
prompt_for_ou

# Attempt to join the domain
print_section "Joining the Domain"
print_color "YELLOW" "Attempting to join the domain $domain_address..."

# Check if realm command is available
if ! command -v realm &> /dev/null; then
    print_color "RED" "❌ 'realm' command not found. Please ensure 'realmd' is installed."
    exit 1
fi

# Create a temporary file to capture the realm join output
temp_output=$(mktemp)

join_command="echo \"$admin_password\" | sudo realm join --verbose --install=/ --user=\"$admin_username\""

if [[ -n "$ou_dn" ]]; then
    join_command+=" --computer-ou=\"$ou_dn\""
fi

join_command+=" \"$domain_address\""

eval "$join_command" &> "$temp_output"
join_status=$?

# Function to verify domain join
verify_domain_join() {
    print_section "Verifying Domain Join"

    # Check if the system is joined to the domain
    if ! realm list | grep -q "$domain_address"; then
        print_color "RED" "❌ System is not joined to the domain. Please check realm status."
        return 1
    fi

    # Verify SSSD service is running
    if ! systemctl is-active --quiet sssd; then
        print_color "RED" "❌ SSSD service is not running. Attempting to start..."
        sudo systemctl start sssd
        sleep 5
        if ! systemctl is-active --quiet sssd; then
            print_color "RED" "❌ Failed to start SSSD service. Please check SSSD logs."
            return 1
        fi
    fi

    # Test SSSD configuration
    if ! getent passwd "${admin_username}@${domain_address}" > /dev/null; then
        print_color "RED" "❌ Failed to retrieve domain user information. SSSD may not be configured correctly."
        return 1
    fi

    print_color "GREEN" "✅ Domain join verified successfully."
    return 0
}

# Additional check to verify domain join status
if realm list | grep -q "$domain_address" || [ $join_status -eq 0 ]; then
    print_color "GREEN" "╔══════════════════════════════════════════════════════════╗"
    print_color "GREEN" "║                                                          ║"
    print_color "GREEN" "║             🎉 Domain Join Successful! 🎉                ║"
    print_color "GREEN" "║                                                          ║"
    print_color "GREEN" "║  Successfully joined domain:                             ║"
    printf "${GREEN}║  %-60s ║${NC}\n" "$domain_address"
    if [[ -n "$ou_dn" ]]; then
        print_color "GREEN" "║                                                          ║"
        print_color "GREEN" "║  Computer account created in OU:                         ║"
        printf "${GREEN}║  %-60s ║${NC}\n" "$ou_dn"
    fi
    print_color "GREEN" "║                                                          ║"
    print_color "GREEN" "╚══════════════════════════════════════════════════════════╝"
    
    # Configure SSSD
    configure_sssd

    # Configure PAM
    configure_pam

    # Install GPO support packages
    install_gpo_packages

    # Configure GPO support
    configure_gpo_support

    # Restart and enable SSSD service
    print_color "YELLOW" "Restarting SSSD service..."
    sudo systemctl restart sssd
    sudo systemctl enable sssd
    print_progress_bar 2

    # Configure NSSwitch
    configure_nsswitch

    # Optional: Allow domain users to sudo
    if prompt_yes_no "Do you want to allow domain users to use sudo?"; then
        configure_sudo_for_domain_users
    fi

    # Test user lookup
    test_user_lookup

    print_section "Final Steps"
    print_color "GREEN" "✅ Domain join process completed successfully with GPO support!"
    print_color "YELLOW" "Please review the following important information:"
    print_color "YELLOW" "1. A backup of your original configuration files has been created in /root/ad_join_backup_*"
    print_color "YELLOW" "2. If you encounter any issues, you can restore these files and run the script again."
    print_color "YELLOW" "3. It's recommended to test domain user login before logging out of your current session."
    print_color "YELLOW" "4. You may need to configure your applications to use domain authentication."
    print_color "YELLOW" "5. GPO support has been enabled. Policies should be applied after the next reboot."

    # Prompt for reboot
    print_color "YELLOW" "A reboot is STRONGLY recommended to apply all changes and ensure proper functionality."
    if prompt_yes_no "Would you like to reboot now?"; then
        print_color "YELLOW" "Rebooting the system..."
        sudo reboot
    else
        print_color "RED" "⚠️ You chose not to reboot. Please note that some changes may not take effect until you reboot."
        print_color "YELLOW" "It is strongly recommended to reboot as soon as possible."
        log_message "User chose not to reboot after configuration changes"
    fi
else
    print_color "RED" "❌ Failed to join the domain. Here's the error output:"
    cat "$temp_output"
    log_message "Failed to join the domain. Error output: $(cat "$temp_output")"
    print_color "RED" "Please check these common issues:"
    print_color "YELLOW" "1. Incorrect domain address"
    print_color "YELLOW" "2. Incorrect admin username or password"
    print_color "YELLOW" "3. The admin account doesn't have sufficient privileges to join the domain"
    print_color "YELLOW" "4. Network connectivity issues"
    print_color "YELLOW" "5. DNS configuration problems"
    print_color "YELLOW" "6. Firewall blocking necessary ports"
    print_color "YELLOW" "7. Time synchronization issues"
    print_color "YELLOW" "8. Encryption type mismatches between client and server"
    print_color "YELLOW" "9. SSSD configuration issues"
    print_color "YELLOW" "10. Specified OU doesn't exist or you don't have permissions to create computer accounts in it"
    print_color "RED" "Please address these issues and try running the script again."
    log_message "Domain join failed. Advised to check common issues."
    
    if prompt_yes_no "Would you like to try again?"; then
        print_color "YELLOW" "Restarting the script..."
        log_message "Restarting the script"
        if [ -x "$0" ]; then
            exec "$0"
        else
            print_color "RED" "❌ Unable to restart the script due to permissions."
            print_color "YELLOW" "Please run the script again manually using: sudo $0"
            log_message "Unable to restart script due to permissions"
            exit 1
        fi
    else
        print_color "YELLOW" "Script execution cancelled. Goodbye! 👋"
        log_message "Script execution cancelled by user"
    fi
fi

# Remove the temporary file
rm -f "$temp_output"

# Final checks
print_section "Final Checks"

# Check SSSD service status
if systemctl is-active --quiet sssd; then
    print_color "GREEN" "✅ SSSD service is running."
else
    print_color "RED" "❌ SSSD service is not running. Please check the logs and restart the service manually."
    log_message "SSSD service not running after script completion"
fi

# Verify domain join status
if realm list | grep -q "$domain_address"; then
    print_color "GREEN" "✅ System is joined to the domain $domain_address."
else
    print_color "RED" "❌ System does not appear to be joined to the domain. Please check realm status manually."
    log_message "System not joined to domain after script completion"
fi

# Check NSSwitch configuration
if grep -q "passwd:.*sss" /etc/nsswitch.conf && grep -q "group:.*sss" /etc/nsswitch.conf; then
    print_color "GREEN" "✅ NSSwitch configuration is correct."
else
    print_color "RED" "❌ NSSwitch configuration may be incorrect. Please check /etc/nsswitch.conf manually."
    log_message "NSSwitch configuration may be incorrect after script completion"
fi

# Clear SSSD cache and restart services
sudo sss_cache -E
sudo systemctl restart sssd

# Log script completion
log_message "Domain join script completed execution"

print_color "GREEN" "Script execution completed. Thank you for using the Domain Join Script! 🚀"
print_color "YELLOW" "If you encounter any issues, please check the log file at /var/log/domain_join.log"

# Cleanup
unset admin_password  # Remove the password from memory

exit 0
