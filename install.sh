#!/bin/bash

set -e

echo "========================================="
echo "        WP GUARD SETUP INSTALLER"
echo "========================================="

# ================= ROOT CHECK =================
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "ERROR: Installer must be run as root"
    echo ""
    echo "Use:"
    echo "sudo bash install.sh"
    echo ""
    exit 1
fi

echo "[OK] Running as root"

# ================= OS DETECT =================
OS=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
    echo "Unsupported OS. Only Debian/Ubuntu supported."
    exit 1
fi

# ================= INSTALL PACKAGES =================
echo "[+] Installing required packages"

apt update

DEPS=(
    mariadb-client
    php-cli
    php-mysql
)

for pkg in "${DEPS[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        echo "Installing $pkg"
        apt install -y "$pkg"
    else
        echo "$pkg already installed"
    fi
done

# ================= CHECK MYSQL ROOT ACCESS =================
echo "[+] Checking MySQL root access"

if ! mysql -u root -e "SELECT 1" >/dev/null 2>&1; then
    echo ""
    echo "ERROR: Cannot access MySQL as root"
    echo "Make sure you run installer on DB server"
    exit 1
fi

# ================= CREATE PROVISIONER USER =================
echo "[+] Creating DB provisioner user"

DB_USER="provisioner"
DB_PASS=$(openssl rand -hex 16)

mysql -u root <<EOF
CREATE USER IF NOT EXISTS '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON *.* TO '$DB_USER'@'localhost' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF

echo "[OK] MySQL provisioner created"

# ================= DIRECTORY SETUP =================
echo "[+] Creating directories"

mkdir -p /opt/wp-guard
mkdir -p /etc/wpdbdash
mkdir -p /var/lib/wpdbdash

touch /var/lib/wpdbdash/history.json

chmod 700 /etc/wpdbdash
chmod 755 /opt/wp-guard
chmod 600 /var/lib/wpdbdash/history.json

# ================= INSTALL WP GUARD CTL =================
echo "[+] Installing wpguardctl"

cat > /usr/local/bin/wpguardctl <<'EOF'
#!/bin/bash

CMD=$1
DB=$2

SERVICE="wp-guard-$DB"
SERVICE_FILE="/etc/systemd/system/$SERVICE.service"
DIR="/opt/wp-guard/$DB"

if [ "$CMD" = "install" ]; then

cat > $SERVICE_FILE <<EOL
[Unit]
Description=WP Guard $DB
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash $DIR/worker.sh
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable $SERVICE
systemctl start $SERVICE

elif [ "$CMD" = "remove" ]; then

systemctl stop $SERVICE 2>/dev/null
systemctl disable $SERVICE 2>/dev/null
rm -f $SERVICE_FILE
systemctl daemon-reload

else
    echo "Usage: wpguardctl install|remove <db>"
fi
EOF

chmod +x /usr/local/bin/wpguardctl

# ================= CREATE CONFIG =================
echo "[+] Creating config.php"

cat > /etc/wpdbdash/config.php <<EOF
<?php
return [
  'admin_user' => 'admin',
  'admin_pass' => 'CHANGE_ME',

  'mysql_host' => 'localhost',
  'mysql_port' => 3306,
  'mysql_user' => '$DB_USER',
  'mysql_pass' => '$DB_PASS',

  'db_name_prefix' => 'db_',
  'db_user_prefix' => 'u_',

  'name_rand_bytes' => 6,
  'pass_rand_bytes' => 16,

  'grant_host' => '%',

  'wp_db_host' => '127.0.0.1',
  'wp_db_port' => 3306,

  'history_file' => '/var/lib/wpdbdash/history.json',

  'browse_db_prefix' => '',

  'wp_guard' => [
      'install_root' => '/opt/wp-guard',
      'interval' => 3,
      'admin_whitelist' => ['admin']
  ]
];
EOF

chmod 600 /etc/wpdbdash/config.php

# ================= FINAL =================
echo ""
echo "========================================="
echo "       WP GUARD INSTALL COMPLETE"
echo "========================================="
echo ""
echo "Provisioner DB User:"
echo "User: $DB_USER"
echo "Pass: $DB_PASS"
echo ""
echo "IMPORTANT:"
echo "Edit /etc/wpdbdash/config.php"
echo "Change admin dashboard password"
echo ""
echo "Installer must always be run as:"
echo "sudo bash install.sh"
echo ""
