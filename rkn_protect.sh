#!/usr/bin/env bash
# ================================================================
#  rkn_protect.sh — Защита сервера от блокировок РКН/ТСПУ/DPI
#  Совместимо с: Remnawave + VLESS + XTLS-Reality
#  Протестировано: Ubuntu 22.04/24.04, Debian 12 (bookworm), Debian 13 (trixie)
#  Запуск ПОСЛЕ установки Remnawave: sudo bash rkn_protect.sh
# ================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
LOG_FILE="/var/log/rkn-protect.log"

# ──────────────────────────────────────────────────────────────────
# ЛОГИРОВАНИЕ И БАЗОВЫЕ ФУНКЦИИ (Б1)
# ──────────────────────────────────────────────────────────────────

_log_raw() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

info()  {
  echo -e "${GREEN}[*]${NC} $*"
  _log_raw "[INFO]  $*"
}
warn()  {
  echo -e "${YELLOW}[!]${NC} $*"
  _log_raw "[WARN]  $*"
}
error() {
  echo -e "${RED}[ERROR]${NC} $*"
  _log_raw "[ERROR] $*"
  exit 1
}
die() {
  echo -e "${RED}[FATAL]${NC} $*" >&2
  _log_raw "[FATAL] $*"
  exit 1
}

# Проверка на root (Б2)
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  error "Скрипт должен быть запущен от имени root (sudo)"
fi

# run_critical — выполнить команду; при ошибке — завершить скрипт
run_critical() {
  local desc="$1"; shift
  if ! "$@"; then
    die "${desc} — команда завершилась с ошибкой: $*"
  fi
}

_log_raw "════════════════════════════════════════"
_log_raw "Запуск rkn_protect.sh (PID=$$, USER=$(whoami 2>/dev/null || echo root))"

# ──────────────────────────────────────────────────────────────────
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ──────────────────────────────────────────────────────────────────

SERVER_IP=""
get_server_ip() {
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
                curl -s --max-time 5 https://ifconfig.me 2>/dev/null || \
                curl -s --max-time 5 https://icanhazip.com 2>/dev/null || true)
    _log_raw "Внешний IP сервера: ${SERVER_IP:-не определён}"
  fi
  echo "$SERVER_IP"
}

# ──────────────────────────────────────────────────────────────────
# ПРОВЕРКА СОВМЕСТИМОСТИ NFTABLES
# ──────────────────────────────────────────────────────────────────
check_nftables_compat() {
  local KERNEL_VER KERNEL_MAJOR KERNEL_MINOR
  KERNEL_VER=$(uname -r)
  KERNEL_MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
  # Б10: Извлечение только числовой части KERNEL_MINOR
  KERNEL_MINOR=$(echo "$KERNEL_VER" | cut -d. -f2 | tr -cd '0-9')

  _log_raw "Ядро: $KERNEL_VER"

  if [ "$KERNEL_MAJOR" -lt 4 ] || { [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 10 ]; }; then
    echo ""
    warn "Ядро ${KERNEL_VER} слишком старое для полноценного nftables (нужно >= 4.10)."
    warn "nftables может работать в режиме совместимости через iptables-legacy."
    echo ""
    read -r -p "  Продолжить установку nftables на старом ядре? [y/N]: " OLD_KERNEL_OK
    [[ "${OLD_KERNEL_OK,,}" == "y" ]] || { info "nftables пропущен из-за старого ядра"; return 1; }
  fi

  if ! nft add table inet _rkn_compat_test 2>/dev/null; then
    warn "nft не может создать тестовую таблицу — возможно ядро без CONFIG_NF_TABLES"
    nft delete table inet _rkn_compat_test 2>/dev/null || true
    return 1
  fi

  local MANGLE_OK=false
  if nft add chain inet _rkn_compat_test postrouting \
      '{ type filter hook postrouting priority mangle; }' 2>/dev/null && \
     nft add rule inet _rkn_compat_test postrouting 'ip ttl set 128' 2>/dev/null; then
    MANGLE_OK=true
  fi
  nft delete table inet _rkn_compat_test 2>/dev/null || true

  if [ "$MANGLE_OK" = false ]; then
    echo ""
    warn "Ядро не поддерживает nftables mangle/TTL правила."
    warn "TTL-манипуляция работать НЕ БУДЕТ."
    echo ""
    read -r -p "  Продолжить установку? [y/N]: " COMPAT_OK
    [[ "${COMPAT_OK,,}" == "y" ]] || { info "nftables пропущен из-за несовместимости"; return 1; }
  else
    _log_raw "nftables: mangle+TTL работает корректно (ядро ${KERNEL_VER})"
  fi

  return 0
}

check_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    # Б6: Убраны лишние пробелы в case
    case "$ID-$VERSION_CODENAME" in
      debian-bookworm|debian-trixie|ubuntu-jammy|ubuntu-noble|ubuntu-focal) ;;
      *)
        warn "Система $PRETTY_NAME не тестировалась."
        read -r -p "  Продолжить на свой страх и риск? [y/N]: " OSOK
        [[ "${OSOK,,}" == "y" ]] || exit 1
        ;;
    esac
  fi
}
check_os

# ──────────────────────────────────────────────────────────────────
# 1. SYSCTL
# ──────────────────────────────────────────────────────────────────
apply_sysctl() {
  info "Применяю sysctl (hardening, совместимо с BBR/Remnawave)..."

  RFC_NOW=$(sysctl -n net.ipv4.tcp_rfc1337 2>/dev/null || echo "0")
  FWD_NOW=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
  if [ "$RFC_NOW" = "1" ] && [ "$FWD_NOW" = "1" ] && \
     [ -f /etc/sysctl.d/99-rkn-protect.conf ]; then
    info "sysctl уже применён (tcp_rfc1337=1, ip_forward=1) — пропускаю"
    return 0
  fi

  cat > /etc/sysctl.d/99-rkn-protect.conf << 'EOF'
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_mtu_probing = 1
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 32768
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
EOF

  sysctl -p /etc/sysctl.d/99-rkn-protect.conf > /dev/null
  info "sysctl применён"
}

# ──────────────────────────────────────────────────────────────────
# 2. NFTABLES
# ──────────────────────────────────────────────────────────────────
apply_nftables() {
  info "Настраиваю nftables (TTL=128, ICMP фильтры, совместимо с Remnawave)..."

  command -v nft &>/dev/null || { apt-get install -y nftables > /dev/null; }

  # Б7: Идемпотентность
  if nft list table inet rkn_protect >/dev/null 2>&1 && [ -f /etc/nftables.d/rkn-protect.nft ]; then
    info "nftables: правила уже применены — пропускаю"
    return 0
  fi

  check_nftables_compat || return 0

  if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo ""
    warn "Обнаружен активный UFW!"
    warn "UFW использует iptables/xtables, nftables работает независимо от него."
    read -r -p "  Продолжить установку nftables рядом с UFW? [y/N]: " UFW_OK
    [[ "${UFW_OK,,}" == "y" ]] || { info "nftables пропущен"; return; }
    echo ""
  fi

  mkdir -p /etc/nftables.d

  cat > /etc/nftables.d/rkn-protect.nft << 'EOF'
table inet rkn_protect {
  chain postrouting {
    type filter hook postrouting priority mangle; policy accept;
    ip  ttl set 128
    ip6 hoplimit set 128
  }
  chain input {
    type filter hook input priority filter; policy accept;
    tcp flags syn limit rate 200/second burst 500 packets accept
    tcp flags syn drop
    icmp type echo-request drop
    icmpv6 type echo-request drop
    icmp type { timestamp-request, address-mask-request } drop
    icmpv6 type { 139, 140 } drop
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    ip  ttl set 128
  }
}
EOF

  if [ -f /etc/nftables.conf ] && ! grep -q "rkn-protect" /etc/nftables.conf; then
    echo 'include "/etc/nftables.d/rkn-protect.nft"' >> /etc/nftables.conf
  fi

  systemctl enable --now nftables > /dev/null 2>&1 || true
  nft delete table inet rkn_protect 2>/dev/null || true
  nft -f /etc/nftables.d/rkn-protect.nft
  info "nftables правила применены"
}

# ──────────────────────────────────────────────────────────────────
# 3. ЛИМИТЫ ФАЙЛОВЫХ ДЕСКРИПТОРОВ
# ──────────────────────────────────────────────────────────────────
apply_fd_limits() {
  info "Настраиваю лимиты файловых дескрипторов для Xray..."

  DOCKER_LIMIT_NOW=$(grep "LimitNOFILE" /etc/systemd/system/docker.service.d/limits.conf \
    2>/dev/null | awk -F= '{print $2}' || echo "")
  if [ "${DOCKER_LIMIT_NOW}" = "1048576" ] && \
     grep -q "root hard nofile 1048576" /etc/security/limits.d/99-xray.conf 2>/dev/null; then
    info "fd limits уже настроены (1048576) — пропускаю"
    return 0
  fi

  cat > /etc/security/limits.d/99-xray.conf << 'EOF'
* soft nofile 1048576
* hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  mkdir -p /etc/systemd/system/docker.service.d
  cat > /etc/systemd/system/docker.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
EOF

  systemctl daemon-reload

  if systemctl is-active --quiet docker 2>/dev/null; then
    warn "Перезапускаю Docker для применения новых лимитов..."
    if ! timeout 60 systemctl restart docker; then
      warn "Docker не перезапустился за 60 секунд — принудительная остановка..."
      systemctl kill docker 2>/dev/null || true
      sleep 2
      systemctl start docker || die "Не удалось запустить Docker после принудительной остановки"
    fi

    info "Жду запуска Docker..."
    DOCKER_UP=false
    for i in $(seq 1 15); do
      if systemctl is-active --quiet docker 2>/dev/null; then
        DOCKER_UP=true
        break
      fi
      sleep 1
    done

    if [ "$DOCKER_UP" = false ]; then
      die "Docker не поднялся за 15 секунд после перезапуска."
    fi

    if [ -d /opt/remnawave ]; then
      cd /opt/remnawave && timeout 60 docker compose up -d > /dev/null 2>&1 || \
        warn "docker compose up /opt/remnawave завершился с ошибкой — проверьте вручную"
    fi

    BOT_DIR=$(find /root /home -maxdepth 3 -name "docker-compose.yml" 2>/dev/null | \
      xargs grep -l "remnawave_bot" 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
    if [ -n "$BOT_DIR" ] && [ "$BOT_DIR" != "/opt/remnawave" ]; then
      cd "$BOT_DIR" && timeout 60 docker compose up -d > /dev/null 2>&1 || \
        warn "docker compose up $BOT_DIR завершился с ошибкой — проверьте вручную"
    fi
    sleep 5
  fi

  info "Лимиты файловых дескрипторов установлены"
}

# ──────────────────────────────────────────────────────────────────
# 4. DNS-over-TLS
# ──────────────────────────────────────────────────────────────────
configure_dot() {
  info "Настраиваю DNS-over-TLS..."

  if systemctl is-active --quiet systemd-resolved 2>/dev/null && \
     [ -f /etc/systemd/resolved.conf.d/dot.conf ]; then
    TLS_ON=$(resolvectl status 2>/dev/null | grep -i "DNSOverTLS" | grep -i "yes" || true)
    if [ -n "$TLS_ON" ]; then
      info "DNS-over-TLS уже активен (systemd-resolved) — пропускаю"
      return 0
    fi
  elif systemctl is-active --quiet stubby 2>/dev/null && \
       grep -q "127.0.0.1" /etc/resolv.conf 2>/dev/null; then
    info "DNS-over-TLS уже активен (stubby) — пропускаю"
    return 0
  fi

  if systemctl list-units --type=service 2>/dev/null | grep -q "systemd-resolved" || \
     systemctl list-unit-files 2>/dev/null | grep -q "systemd-resolved"; then
    _dot_via_resolved
  else
    info "systemd-resolved не найден — использую stubby"
    _dot_via_stubby
  fi
}

_dot_via_resolved() {
  mkdir -p /etc/systemd/resolved.conf.d
  cat > /etc/systemd/resolved.conf.d/dot.conf << 'EOF'
[Resolve]
DNS=1.1.1.1#cloudflare-dns.com 9.9.9.9#dns.quad9.net
FallbackDNS=1.0.0.1#cloudflare-dns.com 149.112.112.112#dns.quad9.net
DNSOverTLS=yes
DNSSEC=yes
DNSStubListener=yes
ReadEtcHosts=yes
EOF
  cat > /etc/resolv.conf.backup << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

  systemctl restart systemd-resolved 2>/dev/null || true
  ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true

  info "Проверяю DNS после применения DoT..."
  DNS_OK=false
  for i in $(seq 1 20); do
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && \
       getent hosts cloudflare.com > /dev/null 2>&1; then
      DNS_OK=true
      break
    fi
    sleep 1
  done

  if [ "$DNS_OK" = true ]; then
    info "DNS-over-TLS включён через systemd-resolved"
    rm -f /etc/resolv.conf.backup
  else
    warn "systemd-resolved не ответил — восстанавливаю резервный DNS..."
    rm -f /etc/resolv.conf
    cp /etc/resolv.conf.backup /etc/resolv.conf
    systemctl restart systemd-resolved 2>/dev/null || true
  fi
}

_dot_via_stubby() {
  if ! command -v stubby &>/dev/null; then
    cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    apt-get update -qq
    apt-get install -y stubby > /dev/null || { warn "Не удалось установить stubby"; return; }
  fi

  cat > /etc/stubby/stubby.yml << 'EOF'
resolution_type: GETDNS_RESOLUTION_STUB
dns_transport_list:
  - GETDNS_TRANSPORT_TLS
tls_authentication: GETDNS_AUTHENTICATION_REQUIRED
tls_query_padding_blocksize: 128
edns_client_subnet_private: 1
round_robin_upstreams: 1
listen_addresses:
  - 127.0.0.1@53
  - 0::1@53
upstream_recursive_servers:
  - address_data: 77.88.8.8
    tls_auth_name: "common.dot.yandex.net"
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
EOF

  systemctl enable --now stubby > /dev/null 2>&1

  info "Жду запуска stubby..."
  STUBBY_OK=false
  for i in $(seq 1 15); do
    # Б13: Fallback для dig
    if command -v dig >/dev/null 2>&1; then
      dig +short +timeout=2 google.com @127.0.0.1 > /dev/null 2>&1 && STUBBY_OK=true
    else
      getent hosts google.com > /dev/null 2>&1 && STUBBY_OK=true
    fi
    [ "$STUBBY_OK" = true ] && break
    sleep 1
  done

  if [ "$STUBBY_OK" = true ]; then
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    if [ -d /etc/NetworkManager/conf.d ]; then
      echo -e "[main]\ndns=none" > /etc/NetworkManager/conf.d/no-dns.conf
      systemctl reload NetworkManager 2>/dev/null || true
    fi
    info "DNS-over-TLS включён через stubby"
  else
    warn "stubby не ответил вовремя"
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
  fi
}

# ──────────────────────────────────────────────────────────────────
# 5. СМЕНА ПОРТА SSH
# ──────────────────────────────────────────────────────────────────
change_ssh_port() {
  info "Смена порта SSH..."
  SSHD_CONFIG="/etc/ssh/sshd_config"
  [ -f "$SSHD_CONFIG" ] || error "Файл $SSHD_CONFIG не найден"

  CURRENT_PORT=$(grep -E "^Port " "$SSHD_CONFIG" | awk '{print $2}' | head -1)
  CURRENT_PORT=${CURRENT_PORT:-22}

  while true; do
    NEW_PORT=$(shuf -i 49152-65535 -n 1)
    if ! ss -tuln | grep -q ":${NEW_PORT} "; then break; fi
  done

  echo ""
  echo -e "${YELLOW}  Текущий порт SSH : ${CURRENT_PORT}${NC}"
  echo -e "${GREEN}  Новый порт SSH   : ${NEW_PORT}${NC}"
  read -r -p "  Продолжить? [y/N]: " CONFIRM
  [[ "${CONFIRM,,}" == "y" ]] || { info "Смена порта отменена"; return; }

  info "Проверяю доступность порта ${NEW_PORT} снаружи..."
  # Б3: Использование get_server_ip
  local CURRENT_IP
  CURRENT_IP=$(get_server_ip)

  PORT_REACHABLE=false
  if [ -n "$CURRENT_IP" ]; then
    if command -v nc &>/dev/null; then
      # Б4: Исправлен синтаксис netcat (-p удалено при -l)
      nc -l "${NEW_PORT}" > /dev/null 2>&1 &
      NC_PID=$!
      sleep 1
      CHECK_RESULT=$(curl -s --max-time 7 \
        "https://portchecker.co/api/v1/query" \
        -H "Content-Type: application/json" \
        -d "{\"host\":\"${CURRENT_IP}\",\"ports\":[${NEW_PORT}]}" 2>/dev/null || true)
      kill $NC_PID 2>/dev/null || true
      if echo "$CHECK_RESULT" | grep -q '"isOpen":true'; then
        PORT_REACHABLE=true
        info "✓ Порт ${NEW_PORT} доступен снаружи"
      fi
    fi
  fi

  if [ "$PORT_REACHABLE" = false ]; then
    warn "Не удалось подтвердить что порт доступен снаружи."
    read -r -p "  Всё равно сменить порт? [y/N]: " FORCE_CONFIRM
    [[ "${FORCE_CONFIRM,,}" == "y" ]] || return
  fi

  if command -v ufw &>/dev/null; then
    ufw allow "${NEW_PORT}/tcp" comment 'SSH new port' > /dev/null
  fi

  if grep -qE "^Port " "$SSHD_CONFIG"; then
    sed -i "s/^Port .*/Port ${NEW_PORT}/" "$SSHD_CONFIG"
  elif grep -qE "^#Port " "$SSHD_CONFIG"; then
    sed -i "s/^#Port .*/Port ${NEW_PORT}/" "$SSHD_CONFIG"
  else
    echo "Port ${NEW_PORT}" >> "$SSHD_CONFIG"
  fi

  if ! sshd -t 2>/dev/null; then
    error "Ошибка в конфиге sshd — откатываем изменения"
    sed -i "s/^Port .*/Port ${CURRENT_PORT}/" "$SSHD_CONFIG"
    return 1
  fi

  systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || error "Не удалось перезапустить sshd"

  if command -v ufw &>/dev/null; then
    if ufw status | grep -qE "^22/tcp|^22 "; then
      ufw delete allow 22/tcp > /dev/null 2>&1 || true
    fi
    ufw reload > /dev/null 2>&1 || true
  fi

  DISPLAY_IP=${CURRENT_IP:-YOUR_SERVER_IP}
  info "SSH порт успешно изменён! Подключение: ssh -p ${NEW_PORT} user@${DISPLAY_IP}"
}

# ──────────────────────────────────────────────────────────────────
# 6. АВТОЗАПУСК
# ──────────────────────────────────────────────────────────────────
install_service() {
  info "Устанавливаю systemd сервис для автозапуска..."
  cat > /etc/systemd/system/rkn-protect.service << 'EOF'
[Unit]
Description=RKN Protection
After=network.target docker.service nftables.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'sysctl -p /etc/sysctl.d/99-rkn-protect.conf >/dev/null && nft -f /etc/nftables.d/rkn-protect.nft'
ExecStop=/bin/bash -c 'nft delete table inet rkn_protect 2>/dev/null || true'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable rkn-protect.service > /dev/null
  info "Сервис установлен"
}

# ──────────────────────────────────────────────────────────────────
# 7. FAIL2BAN
# ──────────────────────────────────────────────────────────────────
configure_fail2ban() {
  info "Устанавливаю и настраиваю Fail2ban..."
  if ! command -v fail2ban-client &>/dev/null; then
    apt-get update -qq && apt-get install -y fail2ban > /dev/null
  fi

  SSH_PORT=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
  SSH_PORT=${SSH_PORT:-22}

  if systemctl is-active --quiet systemd-journald 2>/dev/null; then
    F2B_BACKEND="systemd"; F2B_LOGPATH=""
  else
    F2B_BACKEND="auto"; F2B_LOGPATH='logpath = /var/log/auth.log'
  fi

  if command -v nft &>/dev/null && systemctl is-active --quiet nftables 2>/dev/null; then
    F2B_BANACTION="nftables-multiport"; F2B_BANACTION_ALLPORTS="nftables-allports"
  else
    F2B_BANACTION="iptables-multiport"; F2B_BANACTION_ALLPORTS="iptables-allports"
  fi

  cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16
findtime  = 600
maxretry  = 5
bantime   = 3600
backend = ${F2B_BACKEND}
banaction = ${F2B_BANACTION}
banaction_allports = ${F2B_BANACTION_ALLPORTS}

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
${F2B_LOGPATH}

[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = %(action_)s
bantime  = 86400
findtime = 86400
maxretry = 3
EOF

  systemctl enable fail2ban > /dev/null
  systemctl restart fail2ban
  sleep 2
  if fail2ban-client status sshd &>/dev/null; then
    info "Fail2ban настроен"
  fi
}

# ──────────────────────────────────────────────────────────────────
# 8. SSH HARDENING
# ──────────────────────────────────────────────────────────────────
harden_ssh() {
  info "Применяю SSH hardening..."
  SSHD_CONFIG="/etc/ssh/sshd_config"

  # Б8: Обработка неинтерактивного режима
  if [ ! -t 0 ]; then
    warn "Неинтерактивный режим: применяю SSH hardening по умолчанию"
  else
    warn "SSH hardening отключит AllowTcpForwarding. Это сломает SSH-туннели."
    read -r -p "  Продолжить? [y/N]: " SSH_HARDEN_OK
    [[ "${SSH_HARDEN_OK,,}" == "y" ]] || { info "SSH hardening пропущен"; return; }
  fi

  cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

  set_sshd_param() {
    local param="$1" value="$2"
    if grep -qE "^#?[[:space:]]*${param}[[:space:]]" "$SSHD_CONFIG"; then
      sed -i "s|^#\?[[:space:]]*${param}[[:space:]].*|${param} ${value}|" "$SSHD_CONFIG"
    else
      echo "${param} ${value}" >> "$SSHD_CONFIG"
    fi
  }

  set_sshd_param "MaxAuthTries"          "3"
  set_sshd_param "MaxSessions"           "3"
  set_sshd_param "X11Forwarding"         "no"
  set_sshd_param "AllowTcpForwarding"    "no"
  set_sshd_param "AllowAgentForwarding"  "no"
  set_sshd_param "Compression"           "no"

  if sshd -t 2>/dev/null; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    info "SSH hardening применён"
  else
    warn "Ошибка в конфиге sshd — откатываю изменения"
    LATEST_BAK=$(ls -t ${SSHD_CONFIG}.bak.* 2>/dev/null | head -1)
    [ -n "$LATEST_BAK" ] && cp "$LATEST_BAK" "$SSHD_CONFIG" || true
  fi
}

# ──────────────────────────────────────────────────────────────────
# 9. ОТКЛЮЧЕНИЕ ПРОТОКОЛОВ
# ──────────────────────────────────────────────────────────────────
disable_unused_protocols() {
  info "Отключаю неиспользуемые сетевые протоколы..."
  BLOCKED=$(grep -c "install .* /bin/false" /etc/modprobe.d/unused-protocols.conf 2>/dev/null || echo "0")
  LOADED=$(lsmod 2>/dev/null | grep -cE "^(dccp|sctp|rds|tipc)" || echo "0")
  if [ "$BLOCKED" -ge 4 ] && [ "$LOADED" = "0" ]; then
    info "Протоколы уже отключены — пропускаю"
    return 0
  fi

  cat > /etc/modprobe.d/unused-protocols.conf << 'EOF'
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
EOF

  for proto in dccp sctp rds tipc; do
    lsmod | grep -q "^${proto}" && modprobe -r "$proto" 2>/dev/null || true
  done
  update-initramfs -u 2>/dev/null || true
  info "Протоколы dccp, sctp, rds, tipc отключены"
}

# ──────────────────────────────────────────────────────────────────
# СТАТУС
# ──────────────────────────────────────────────────────────────────
status_check() {
  local OK="${GREEN}✓${NC}" FAIL="${RED}✗${NC}" WARN="${YELLOW}~${NC}"
  echo -e "\n${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║         RKN Protect — статус модулей                ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}\n"

  # Б5: Добавлено fallback значение при пустом выводе
  RFC=$(sysctl -n net.ipv4.tcp_rfc1337 2>/dev/null || echo "0")
  FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
  if [ "$RFC" = "1" ] && [ "$FWD" = "1" ]; then
    echo -e "  ${OK} sysctl       tcp_rfc1337=1, ip_forward=1"
  else
    echo -e "  ${FAIL} sysctl       не настроен"
  fi

  if nft list table inet rkn_protect > /dev/null 2>&1; then
    echo -e "  ${OK} nftables     таблица rkn_protect активна"
  else
    echo -e "  ${FAIL} nftables     не настроен"
  fi

  DOCKER_LIMIT=$(grep LimitNOFILE /etc/systemd/system/docker.service.d/limits.conf 2>/dev/null | awk -F= '{print $2}' || true)
  if [ "${DOCKER_LIMIT}" = "1048576" ]; then
    echo -e "  ${OK} fd limits    nofile=1048576"
  else
    echo -e "  ${FAIL} fd limits    не настроен"
  fi

  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | awk -F: '{print $2}' | xargs || echo "?")
    # Б11: Корректный парсинг BANACT
    BANACT=$(grep "^banaction" /etc/fail2ban/jail.local 2>/dev/null | awk -F'=' '{print $2}' | xargs || echo "default")
    echo -e "  ${OK} fail2ban     активен, забанено: ${BANNED}, бэкенд: ${BANACT}"
  else
    echo -e "  ${FAIL} fail2ban     не настроен"
  fi
  echo ""
}

# ──────────────────────────────────────────────────────────────────
# ОТКАТ
# ──────────────────────────────────────────────────────────────────
rollback() {
  echo -e "\n${RED}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${RED}║              Откат изменений RKN Protect            ║${NC}"
  echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}\n"
  echo "  1) nftables  2) sysctl  3) SSH  4) Fail2ban  5) Сервис  6) Всё  0) Отмена"
  read -r -p "  Ваш выбор: " RB_CHOICE

  # Б9: Использование независимых if блоков вместо ломающегося case-fallthrough
  if [[ "$RB_CHOICE" == "1" || "$RB_CHOICE" == "6" ]]; then
    nft delete table inet rkn_protect 2>/dev/null && info "nftables: таблица удалена"
    sed -i '/rkn-protect/d' /etc/nftables.conf 2>/dev/null || true
    rm -f /etc/nftables.d/rkn-protect.nft
  fi
  if [[ "$RB_CHOICE" == "2" || "$RB_CHOICE" == "6" ]]; then
    rm -f /etc/sysctl.d/99-rkn-protect.conf
    sysctl --system > /dev/null 2>&1 || true
    info "sysctl: конфиг удалён"
  fi
  if [[ "$RB_CHOICE" == "3" || "$RB_CHOICE" == "6" ]]; then
    SSHD_CONFIG="/etc/ssh/sshd_config"
    LATEST_BAK=$(ls -t "${SSHD_CONFIG}".bak.* 2>/dev/null | head -1)
    if [ -n "$LATEST_BAK" ]; then
      cp "$LATEST_BAK" "$SSHD_CONFIG"
      systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
      info "SSH: восстановлен из ${LATEST_BAK}"
    fi
  fi
  if [[ "$RB_CHOICE" == "4" || "$RB_CHOICE" == "6" ]]; then
    systemctl stop fail2ban 2>/dev/null || true
    rm -f /etc/fail2ban/jail.local
    info "fail2ban: остановлен и jail удалён"
  fi
  if [[ "$RB_CHOICE" == "5" || "$RB_CHOICE" == "6" ]]; then
    systemctl disable --now rkn-protect.service > /dev/null 2>&1 || true
    rm -f /etc/systemd/system/rkn-protect.service
    systemctl daemon-reload
    info "сервис: удалён"
  fi
  if [[ "$RB_CHOICE" == "0" ]]; then
    info "Откат отменён"
  fi
}

# ──────────────────────────────────────────────────────────────────
# ГЛАВНОЕ МЕНЮ
# ──────────────────────────────────────────────────────────────────
echo -e "\n============================================="
echo " RKN Protect — совместимо с Remnawave"
echo "=============================================\n"
echo "  1) sysctl hardening"
echo "  2) nftables (TTL=128 + ICMP)"
echo "  3) Лимиты fd для Xray"
echo "  4) DNS-over-TLS"
echo "  5) Fail2ban"
echo "  6) SSH hardening"
echo "  7) Отключение протоколов"
echo "  8) Сменить порт SSH"
echo "  9) Установить всё (1–7) + автозапуск"
echo " 10) Статус всех модулей"
echo " 11) Откат изменений"
read -r -p "Ваш выбор [1-11, Enter=9]: " CHOICE
_log_raw "Выбор пользователя: ${CHOICE:-9}"

case "${CHOICE:-9}" in
  1) apply_sysctl ;;
  2) apply_nftables ;;
  3) apply_fd_limits ;;
  4) configure_dot ;;
  5) configure_fail2ban ;;
  6) harden_ssh ;;
  7) disable_unused_protocols ;;
  8) change_ssh_port ;;
  9|"")
    apply_sysctl
    apply_nftables
    apply_fd_limits
    configure_dot
    configure_fail2ban
    harden_ssh
    disable_unused_protocols
    install_service
    ;;
  10) status_check ;;
  11) rollback ;;
  *) error "Неверный выбор" ;;
esac

# Б12: Скрытие вывода коннекта при вызове статус/откат
if [[ "$CHOICE" != "10" && "$CHOICE" != "11" ]]; then
  echo ""
  info "Готово!"
  _FINAL_IP=$(get_server_ip)
  if [ -n "$_FINAL_IP" ]; then
    SSH_PORT_FINAL=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    SSH_PORT_FINAL=${SSH_PORT_FINAL:-22}
    echo -e "  ${GREEN}Подключение к серверу:${NC}"
    echo -e "  ${YELLOW}ssh -p ${SSH_PORT_FINAL} user@${_FINAL_IP}${NC}\n"
  fi
fi

_log_raw "Скрипт завершён"
