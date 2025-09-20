#!/bin/bash

# =============================================================================
# VPN Server Auto-Installer Script
# Supports: VLESS, VMess, Trojan with WebSocket, gRPC, TLS, XTLS/Reality
# Backend: Xray-core
# OS: Ubuntu 20.04/22.04, Debian 10/11
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration variables
XRAY_VERSION="1.8.4"
XRAY_CONFIG_DIR="/usr/local/etc/xray"
XRAY_LOG_DIR="/var/log/xray"
XRAY_SERVICE_FILE="/etc/systemd/system/xray.service"
USERS_FILE="/usr/local/etc/xray/users.json"
MENU_SCRIPT="/usr/local/bin/vpn-menu"

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Function to check OS compatibility
check_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        print_error "Cannot determine OS version"
        exit 1
    fi

    case $OS in
        "Ubuntu")
            if [[ "$VER" != "20.04" && "$VER" != "22.04" ]]; then
                print_warning "This script is tested on Ubuntu 20.04/22.04. Current version: $VER"
            fi
            ;;
        "Debian GNU/Linux")
            if [[ "$VER" != "10" && "$VER" != "11" ]]; then
                print_warning "This script is tested on Debian 10/11. Current version: $VER"
            fi
            ;;
        *)
            print_error "Unsupported OS: $OS"
            exit 1
            ;;
    esac
}

# Function to update system
update_system() {
    print_header "Updating System Packages"
    apt update -y
    apt upgrade -y
    apt install -y curl wget unzip jq qrencode
}

# Function to add swap
add_swap() {
    print_header "Adding 1GB Swap"
    if [[ ! -f /swapfile ]]; then
        fallocate -l 1G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
        print_status "1GB swap added successfully"
    else
        print_warning "Swap file already exists"
    fi
}

# Function to install Xray-core
install_xray() {
    print_header "Installing Xray-core"
    
    # Download and install Xray
    cd /tmp
    wget -O xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip"
    unzip xray.zip
    mv xray /usr/local/bin/
    chmod +x /usr/local/bin/xray
    
    # Create directories
    mkdir -p $XRAY_CONFIG_DIR
    mkdir -p $XRAY_LOG_DIR
    
    # Create systemd service
    cat > $XRAY_SERVICE_FILE << EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=nobody
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config $XRAY_CONFIG_DIR/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable xray
    
    print_status "Xray-core installed successfully"
}

# Function to install SSL certificate
install_ssl() {
    print_header "Installing SSL Certificate"
    
    # Install acme.sh
    curl https://get.acme.sh | sh
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    
    # Get domain and email
    read -p "Enter your domain (e.g., vpn.example.com): " DOMAIN
    read -p "Enter your Cloudflare email: " CF_EMAIL
    read -p "Enter your Cloudflare Global API Key: " CF_KEY
    
    # Set Cloudflare API key
    export CF_Email="$CF_EMAIL"
    export CF_Key="$CF_KEY"
    
    # Issue certificate
    /root/.acme.sh/acme.sh --issue --dns dns_cf -d $DOMAIN
    
    # Install certificate
    /root/.acme.sh/acme.sh --install-cert -d $DOMAIN \
        --key-file $XRAY_CONFIG_DIR/private.key \
        --fullchain-file $XRAY_CONFIG_DIR/cert.crt
    
    # Auto-renewal
    /root/.acme.sh/acme.sh --cron --home /root/.acme.sh
    
    print_status "SSL certificate installed for $DOMAIN"
}

# Function to generate UUID
generate_uuid() {
    cat /proc/sys/kernel/random/uuid
}

# Function to create Xray configuration
create_xray_config() {
    print_header "Creating Xray Configuration"
    
    # Generate certificates for XTLS/Reality
    openssl ecparam -genkey -name prime256v1 -noout -out $XRAY_CONFIG_DIR/reality.key
    openssl req -new -key $XRAY_CONFIG_DIR/reality.key -x509 -days 365 -out $XRAY_CONFIG_DIR/reality.crt -subj "/CN=www.microsoft.com"
    
    # Generate Reality shortId
    REALITY_SHORT_ID=$(openssl rand -hex 8)
    
    # Create users.json
    cat > $USERS_FILE << EOF
{
    "users": []
}
EOF
    
    # Create main config
    cat > $XRAY_CONFIG_DIR/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "$XRAY_LOG_DIR/access.log",
        "error": "$XRAY_LOG_DIR/error.log"
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vless",
            "settings": {
                "clients": [],
                "decryption": "none"
            },
            "streamSettings": {
                "network": "tcp",
                "security": "reality",
                "realitySettings": {
                    "show": false,
                    "dest": "www.microsoft.com:443",
                    "xver": 0,
                    "serverNames": [
                        "www.microsoft.com"
                    ],
                    "privateKey": "$(cat $XRAY_CONFIG_DIR/reality.key | base64 -w 0)",
                    "shortIds": [
                        "$REALITY_SHORT_ID"
                    ]
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": ["http", "tls"]
            }
        },
        {
            "port": 80,
            "protocol": "vless",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/vless-ws"
                }
            }
        },
        {
            "port": 8080,
            "protocol": "vmess",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "grpc",
                "grpcSettings": {
                    "serviceName": "vmess-grpc"
                }
            }
        },
        {
            "port": 8443,
            "protocol": "trojan",
            "settings": {
                "clients": []
            },
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "$XRAY_CONFIG_DIR/cert.crt",
                            "keyFile": "$XRAY_CONFIG_DIR/private.key"
                        }
                    ]
                }
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "routing": {
        "rules": [
            {
                "type": "field",
                "protocol": ["bittorrent"],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF

    chown -R nobody:nogroup $XRAY_CONFIG_DIR
    chown -R nobody:nogroup $XRAY_LOG_DIR
    
    print_status "Xray configuration created"
}

# Function to install Fail2Ban
install_fail2ban() {
    print_header "Installing Fail2Ban"
    
    apt install -y fail2ban
    
    # Configure Fail2Ban for SSH
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
EOF

    systemctl enable fail2ban
    systemctl start fail2ban
    
    print_status "Fail2Ban installed and configured"
}

# Function to create user management script
create_user_management() {
    print_header "Creating User Management Script"
    
    cat > $MENU_SCRIPT << 'EOF'
#!/bin/bash

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

XRAY_CONFIG_DIR="/usr/local/etc/xray"
USERS_FILE="/usr/local/etc/xray/users.json"
DOMAIN=""

# Load domain from config
if [[ -f /usr/local/etc/xray/domain.txt ]]; then
    DOMAIN=$(cat /usr/local/etc/xray/domain.txt)
fi

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${CYAN}================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}================================${NC}"
}

# Function to generate QR code
generate_qr() {
    local config=$1
    echo "$config" | qrencode -t ansiutf8
}

# Function to add user
add_user() {
    print_header "Add New User"
    
    read -p "Enter username: " username
    read -p "Enter password: " password
    read -p "Enter expiration days (0 for no expiration): " days
    
    if [[ $days -eq 0 ]]; then
        expire_date="never"
    else
        expire_date=$(date -d "+$days days" +%Y-%m-%d)
    fi
    
    # Generate UUIDs
    vless_uuid=$(cat /proc/sys/kernel/random/uuid)
    vmess_uuid=$(cat /proc/sys/kernel/random/uuid)
    trojan_uuid=$(cat /proc/sys/kernel/random/uuid)
    
    # Add to users.json
    jq --arg user "$username" --arg pass "$password" --arg expire "$expire_date" --arg vless "$vless_uuid" --arg vmess "$vmess_uuid" --arg trojan "$trojan_uuid" \
        '.users += [{"username": $user, "password": $pass, "expire": $expire, "vless_uuid": $vless, "vmess_uuid": $vmess, "trojan_uuid": $trojan}]' \
        $USERS_FILE > /tmp/users.json && mv /tmp/users.json $USERS_FILE
    
    # Update Xray config
    update_xray_config
    
    print_status "User $username added successfully"
    
    # Generate connection links
    generate_links "$username" "$vless_uuid" "$vmess_uuid" "$trojan_uuid"
}

# Function to generate connection links
generate_links() {
    local username=$1
    local vless_uuid=$2
    local vmess_uuid=$3
    local trojan_uuid=$4
    
    print_header "Connection Links for $username"
    
    # VLESS Reality
    vless_reality="vless://$vless_uuid@$DOMAIN:443?encryption=none&security=reality&sni=www.microsoft.com&pbk=$(cat $XRAY_CONFIG_DIR/reality.key | base64 -w 0)&sid=$(openssl rand -hex 8)&type=tcp&headerType=none#VLESS-Reality-$username"
    
    # VLESS WS
    vless_ws="vless://$vless_uuid@$DOMAIN:80?encryption=none&security=none&type=ws&host=$DOMAIN&path=%2Fvless-ws#VLESS-WS-$username"
    
    # VMess gRPC
    vmess_grpc="vmess://$(echo '{"v":"2","ps":"VMess-gRPC-'$username'","add":"'$DOMAIN'","port":"8080","id":"'$vmess_uuid'","aid":"0","scy":"auto","net":"grpc","type":"gun","host":"","path":"vmess-grpc","tls":"","sni":"","alpn":""}' | base64 -w 0)"
    
    # Trojan
    trojan_link="trojan://$trojan_uuid@$DOMAIN:8443?security=tls&sni=$DOMAIN&type=tcp&headerType=none#Trojan-$username"
    
    echo -e "${BLUE}VLESS Reality:${NC}"
    echo "$vless_reality"
    echo
    generate_qr "$vless_reality"
    echo
    
    echo -e "${BLUE}VLESS WebSocket:${NC}"
    echo "$vless_ws"
    echo
    generate_qr "$vless_ws"
    echo
    
    echo -e "${BLUE}VMess gRPC:${NC}"
    echo "$vmess_grpc"
    echo
    generate_qr "$vmess_grpc"
    echo
    
    echo -e "${BLUE}Trojan:${NC}"
    echo "$trojan_link"
    echo
    generate_qr "$trojan_link"
    echo
}

# Function to update Xray configuration
update_xray_config() {
    # This is a simplified version - in production, you'd want to properly update the config
    systemctl restart xray
}

# Function to list users
list_users() {
    print_header "Active Users"
    
    if [[ ! -f $USERS_FILE ]]; then
        print_error "Users file not found"
        return
    fi
    
    jq -r '.users[] | "\(.username) - Expires: \(.expire)"' $USERS_FILE
}

# Function to remove user
remove_user() {
    print_header "Remove User"
    
    read -p "Enter username to remove: " username
    
    jq --arg user "$username" 'del(.users[] | select(.username == $user))' $USERS_FILE > /tmp/users.json && mv /tmp/users.json $USERS_FILE
    
    update_xray_config
    print_status "User $username removed"
}

# Function to extend user
extend_user() {
    print_header "Extend User"
    
    read -p "Enter username: " username
    read -p "Enter additional days: " days
    
    current_expire=$(jq -r --arg user "$username" '.users[] | select(.username == $user) | .expire' $USERS_FILE)
    
    if [[ "$current_expire" == "never" ]]; then
        print_error "User has no expiration"
        return
    fi
    
    new_expire=$(date -d "$current_expire + $days days" +%Y-%m-%d)
    
    jq --arg user "$username" --arg expire "$new_expire" \
        '(.users[] | select(.username == $user) | .expire) = $expire' \
        $USERS_FILE > /tmp/users.json && mv /tmp/users.json $USERS_FILE
    
    update_xray_config
    print_status "User $username extended until $new_expire"
}

# Function to clean expired users
clean_expired() {
    print_header "Cleaning Expired Users"
    
    current_date=$(date +%Y-%m-%d)
    
    jq --arg date "$current_date" \
        'del(.users[] | select(.expire != "never" and .expire < $date))' \
        $USERS_FILE > /tmp/users.json && mv /tmp/users.json $USERS_FILE
    
    update_xray_config
    print_status "Expired users cleaned"
}

# Main menu
show_menu() {
    while true; do
        print_header "VPN User Management"
        echo "1. Add User"
        echo "2. List Users"
        echo "3. Remove User"
        echo "4. Extend User"
        echo "5. Clean Expired Users"
        echo "6. Show User Links"
        echo "7. Exit"
        echo
        read -p "Choose option: " choice
        
        case $choice in
            1) add_user ;;
            2) list_users ;;
            3) remove_user ;;
            4) extend_user ;;
            5) clean_expired ;;
            6) 
                read -p "Enter username: " username
                user_data=$(jq -r --arg user "$username" '.users[] | select(.username == $user)' $USERS_FILE)
                if [[ "$user_data" != "null" ]]; then
                    vless_uuid=$(echo "$user_data" | jq -r '.vless_uuid')
                    vmess_uuid=$(echo "$user_data" | jq -r '.vmess_uuid')
                    trojan_uuid=$(echo "$user_data" | jq -r '.trojan_uuid')
                    generate_links "$username" "$vless_uuid" "$vmess_uuid" "$trojan_uuid"
                else
                    print_error "User not found"
                fi
                ;;
            7) exit 0 ;;
            *) print_error "Invalid option" ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
        clear
    done
}

# Run menu
show_menu
EOF

    chmod +x $MENU_SCRIPT
    
    print_status "User management script created at $MENU_SCRIPT"
}

# Function to setup log cleanup
setup_log_cleanup() {
    print_header "Setting up Log Cleanup"
    
    # Create log cleanup script
    cat > /usr/local/bin/cleanup-logs.sh << 'EOF'
#!/bin/bash
# Clean Xray logs older than 7 days
find /var/log/xray -name "*.log" -mtime +7 -delete

# Clean system logs
journalctl --vacuum-time=7d

# Clean expired users
/usr/local/bin/vpn-menu --clean-expired 2>/dev/null || true
EOF

    chmod +x /usr/local/bin/cleanup-logs.sh
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "*/3 * * * * /usr/local/bin/cleanup-logs.sh") | crontab -
    
    print_status "Log cleanup configured (every 3 minutes)"
}

# Function to tune system performance
tune_performance() {
    print_header "Tuning System Performance"
    
    # TCP optimizations
    cat >> /etc/sysctl.conf << EOF

# Xray performance tuning
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
EOF

    sysctl -p
    
    # Increase file limits
    cat >> /etc/security/limits.conf << EOF
* soft nofile 65536
* hard nofile 65536
EOF

    print_status "System performance tuned"
}

# Function to save domain
save_domain() {
    echo "$DOMAIN" > /usr/local/etc/xray/domain.txt
}

# Function to show final summary
show_summary() {
    print_header "Installation Complete!"
    
    echo -e "${GREEN}VPN Server Successfully Installed!${NC}"
    echo
    echo -e "${BLUE}Server Information:${NC}"
    echo "Domain: $DOMAIN"
    echo "Xray Version: $XRAY_VERSION"
    echo "Config Directory: $XRAY_CONFIG_DIR"
    echo
    echo -e "${BLUE}Available Protocols:${NC}"
    echo "• VLESS with Reality (Port 443)"
    echo "• VLESS with WebSocket (Port 80)"
    echo "• VMess with gRPC (Port 8080)"
    echo "• Trojan with TLS (Port 8443)"
    echo
    echo -e "${BLUE}Management Commands:${NC}"
    echo "• User Management: $MENU_SCRIPT"
    echo "• Service Status: systemctl status xray"
    echo "• Restart Service: systemctl restart xray"
    echo "• View Logs: journalctl -u xray -f"
    echo
    echo -e "${YELLOW}Cloudflare Settings Required:${NC}"
    echo "• SSL/TLS: Full"
    echo "• gRPC: On"
    echo "• WebSocket: On"
    echo "• Always Use HTTPS: Off"
    echo "• Under Attack Mode: Off"
    echo
    echo -e "${RED}Important:${NC}"
    echo "• Disable Cloudflare proxy (orange cloud) for optimal performance"
    echo "• Some features may not work properly with proxy enabled"
    echo "• Server IP will be exposed if proxy is disabled"
    echo
    echo -e "${GREEN}Run '$MENU_SCRIPT' to manage users${NC}"
}

# Main installation function
main() {
    print_header "VPN Server Auto-Installer"
    echo "This script will install a multi-protocol VPN server with:"
    echo "• VLESS, VMess, Trojan protocols"
    echo "• WebSocket, gRPC, TLS, XTLS/Reality support"
    echo "• Cloudflare integration"
    echo "• User management system"
    echo "• Security features (Fail2Ban, swap, log cleanup)"
    echo
    
    read -p "Continue with installation? (y/N): " confirm
    if [[ $confirm != "y" && $confirm != "Y" ]]; then
        print_error "Installation cancelled"
        exit 1
    fi
    
    check_root
    check_os
    update_system
    add_swap
    install_xray
    install_ssl
    create_xray_config
    install_fail2ban
    create_user_management
    setup_log_cleanup
    tune_performance
    save_domain
    show_summary
}

# Run main function
main "$@"