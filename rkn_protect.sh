#!/usr/bin/env bash
# ================================================================
#  rkn_protect.sh — Защита сервера от блокировок РКН/ТСПУ/DPI
#  Совместимо с: Remnawave + VLESS + XTLS-Reality
#  Протестировано: Ubuntu 22.04/24.04, Debian 12
#  Запуск ПОСЛЕ установки Remnawave: sudo bash rkn_protect.sh
# ================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[*]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Запустите скрипт от root (sudo)"

# ──────────────────────────────────────────────────────────────────
# 1. SYSCTL: hardening сетевого стека
#
#    Совместимость с Remnawave:
#    • tcp_timestamps = 1  — ОБЯЗАТЕЛЬНО для BBR. Remnawave включает
#      BBR через /etc/sysctl.conf, BBR использует timestamps для
#      измерения RTT. Отключение = деградация BBR.
#    • ip_forward = 1      — нужен Docker/Remnawave для маршрутизации
#      трафика между контейнерами.
# ──────────────────────────────────────────────────────────────────
apply_sysctl() {
  info "Применяю sysctl (hardening, совместимо с BBR/Remnawave)..."

  cat > /etc/sysctl.d/99-rkn-protect.conf << 'EOF'
# ── Антифингерпринт TCP ─────────────────────────────────────────
# tcp_timestamps = 1: оставляем включёнными.
# BBR (который ставит Remnawave) требует timestamps для RTT.
# Отключение ломает BBR и деградирует производительность VLESS.
net.ipv4.tcp_timestamps = 1

net.ipv4.tcp_sack = 1

# ── Защита от RST-инъекций (метод блокировки РКН) ──────────────
# tcp_rfc1337=1 — защита от TIME_WAIT атак через RST на уровне стека.
# Это безопасная замена RST drop в nftables (который несовместим с Remnawave).
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_synack_retries = 3

# ── IP forwarding — нужен Docker и Remnawave ────────────────────
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1

# ── Минимизируем утечки информации ─────────────────────────────
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

# ── TCP буферы (не конфликтуют с BBR) ──────────────────────────
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_mtu_probing = 1

# ── Оптимизация для Xray / XTLS-Reality ────────────────────────
# Большая очередь входящих соединений (много параллельных VLESS-клиентов)
net.core.somaxconn = 32768
net.ipv4.tcp_max_syn_backlog = 32768

# Переиспользование TIME_WAIT сокетов — ускоряет переподключения клиентов
net.ipv4.tcp_tw_reuse = 1

# Быстрое освобождение закрытых соединений
net.ipv4.tcp_fin_timeout = 15
EOF

  sysctl -p /etc/sysctl.d/99-rkn-protect.conf > /dev/null
  info "sysctl применён"
}

# ──────────────────────────────────────────────────────────────────
# 2. NFTABLES: TTL манипуляция + ICMP фильтрация
#
#    Совместимость с Remnawave:
#    • RST drop НАМЕРЕННО УБРАН — он обрывал TCP-соединения между
#      панелью и нодами Remnawave. Защита от RST-инъекций РКН
#      реализована через tcp_rfc1337=1 в sysctl (безопасно).
#    • TTL=128 применяется в postrouting (после Docker NAT) —
#      весь трафик контейнеров тоже получает правильный TTL.
#    • SYN rate limit поднят до 200/сек — с запасом для
#      одновременных подключений VLESS-клиентов.
# ──────────────────────────────────────────────────────────────────
apply_nftables() {
  info "Настраиваю nftables (TTL=128, ICMP фильтры, совместимо с Remnawave)..."

  command -v nft &>/dev/null || { apt-get install -y nftables > /dev/null; }
  mkdir -p /etc/nftables.d

  cat > /etc/nftables.d/rkn-protect.nft << 'EOF'
table inet rkn_protect {

  chain postrouting {
    type filter hook postrouting priority mangle; policy accept;

    # TTL=128 имитирует Windows-хост.
    # ТСПУ использует TTL для определения ОС и подсчёта хопов.
    # Применяется ко всему исходящему трафику включая Docker-контейнеры Remnawave.
    ip  ttl set 128
    ip6 hoplimit set 128
  }

  chain input {
    type filter hook input priority filter; policy accept;

    # RST drop здесь отсутствует намеренно — несовместим с Remnawave.
    # Защита от RST-инъекций РКН: tcp_rfc1337=1 в sysctl.

    # Защита от SYN-флуда.
    # Лимит 200/сек с запасом покрывает одновременные VLESS-подключения.
    tcp flags syn limit rate 200/second burst 500 packets accept
    tcp flags syn drop

    # Блокируем ICMP timestamp — используется для fingerprinting и uptime-детекции
    icmp type { timestamp-request, address-mask-request } drop

    # Блокируем MLD (IPv6 multicast listener — утечка топологии сети)
    icmpv6 type { 139, 140 } drop
  }

  chain forward {
    type filter hook forward priority filter; policy accept;

    # TTL для форвардируемых пакетов (Docker bridge, трафик нод Remnawave)
    ip  ttl set 128
  }
}
EOF

  # Подключаем к основному конфигу если ещё не добавлено
  if [ -f /etc/nftables.conf ] && ! grep -q "rkn-protect" /etc/nftables.conf; then
    echo 'include "/etc/nftables.d/rkn-protect.nft"' >> /etc/nftables.conf
  fi

  systemctl enable --now nftables > /dev/null 2>&1 || true

  # Удаляем старую таблицу если существует — предотвращаем задвоение правил
  # при повторном запуске скрипта
  nft delete table inet rkn_protect 2>/dev/null || true

  nft -f /etc/nftables.d/rkn-protect.nft
  info "nftables правила применены"
}

# ──────────────────────────────────────────────────────────────────
# 3. ЛИМИТЫ ФАЙЛОВЫХ ДЕСКРИПТОРОВ для Xray в Docker
#
#    Xray обрабатывает много параллельных VLESS-соединений.
#    По умолчанию лимит 1024 — слишком мало при нагрузке.
# ──────────────────────────────────────────────────────────────────
apply_fd_limits() {
  info "Настраиваю лимиты файловых дескрипторов для Xray..."

  cat > /etc/security/limits.d/99-xray.conf << 'EOF'
*    soft nofile 1048576
*    hard nofile 1048576
root soft nofile 1048576
root hard nofile 1048576
EOF

  # Лимиты для systemd-сервиса Docker (в котором работает Xray/Remnawave)
  mkdir -p /etc/systemd/system/docker.service.d
  cat > /etc/systemd/system/docker.service.d/limits.conf << 'EOF'
[Service]
LimitNOFILE=1048576
LimitNPROC=infinity
LimitCORE=infinity
EOF

  systemctl daemon-reload

  # Перезапускаем Docker только если он уже запущен
  if systemctl is-active --quiet docker 2>/dev/null; then
    warn "Перезапускаю Docker для применения новых лимитов..."
    warn "Remnawave контейнеры остановятся на ~10 секунд"
    systemctl restart docker

    # Ждём пока Docker полностью поднимется
    info "Жду запуска Docker..."
    for i in $(seq 1 15); do
      if systemctl is-active --quiet docker 2>/dev/null; then
        break
      fi
      sleep 1
    done

    # Поднимаем обратно контейнеры Remnawave если они есть
    if [ -d /opt/remnawave ]; then
      cd /opt/remnawave && docker compose up -d > /dev/null 2>&1 || true
    fi

    # Поднимаем контейнеры бота если есть
    BOT_DIR=$(find /root /home -maxdepth 3 -name "docker-compose.yml" 2>/dev/null |       xargs grep -l "remnawave_bot" 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
    if [ -n "$BOT_DIR" ] && [ "$BOT_DIR" != "/opt/remnawave" ]; then
      cd "$BOT_DIR" && docker compose up -d > /dev/null 2>&1 || true
    fi

    # Небольшая пауза чтобы контейнеры успели стартовать
    sleep 5
  fi

  info "Лимиты файловых дескрипторов установлены (1048576)"
}

# ──────────────────────────────────────────────────────────────────
# 4. DNS-over-TLS через systemd-resolved
#
#    Предотвращает DNS-спуфинг — основной массовый метод блокировки РКН.
#    Совместимость с Remnawave: Docker использует свой встроенный
#    резолвер (127.0.0.11), не зависящий от systemd-resolved.
#    Конфликтов нет.
# ──────────────────────────────────────────────────────────────────
configure_dot() {
  info "Настраиваю DNS-over-TLS..."

  # Определяем способ настройки DoT
  if systemctl list-units --type=service 2>/dev/null | grep -q "systemd-resolved" ||      systemctl list-unit-files 2>/dev/null | grep -q "systemd-resolved"; then
    _dot_via_resolved
  else
    info "systemd-resolved не найден — использую stubby"
    _dot_via_stubby
  fi
}

# DoT через systemd-resolved (Ubuntu / Debian с resolved)
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

  # Резервный resolv.conf на случай если resolved не поднимется
  cat > /etc/resolv.conf.backup << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF

  systemctl restart systemd-resolved 2>/dev/null || true
  ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true

  info "Проверяю DNS после применения DoT..."
  DNS_OK=false
  for i in $(seq 1 20); do
    if systemctl is-active --quiet systemd-resolved 2>/dev/null &&        getent hosts cloudflare.com > /dev/null 2>&1; then
      DNS_OK=true
      break
    fi
    sleep 1
  done

  if [ "$DNS_OK" = true ]; then
    info "DNS-over-TLS включён через systemd-resolved (Cloudflare + Quad9)"
    rm -f /etc/resolv.conf.backup
  else
    warn "systemd-resolved не ответил — восстанавливаю резервный DNS..."
    rm -f /etc/resolv.conf
    cp /etc/resolv.conf.backup /etc/resolv.conf
    systemctl restart systemd-resolved 2>/dev/null || true
    sleep 3
    if getent hosts cloudflare.com > /dev/null 2>&1; then
      info "DNS восстановлен"
    else
      warn "DNS недоступен — проверьте вручную: systemctl status systemd-resolved"
    fi
  fi
}

# DoT через stubby (Debian без systemd-resolved)
_dot_via_stubby() {
  # Устанавливаем stubby если нет
  if ! command -v stubby &>/dev/null; then
    # Резервный DNS на время установки
    cat > /etc/resolv.conf << 'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    apt-get update -qq
    apt-get install -y stubby > /dev/null || {
      warn "Не удалось установить stubby — DNS-over-TLS пропущен"
      return
    }
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
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"
EOF

  systemctl enable --now stubby > /dev/null 2>&1

  # Ждём пока stubby установит TLS-соединение с upstream (до 15 секунд)
  info "Жду запуска stubby..."
  STUBBY_OK=false
  for i in $(seq 1 15); do
    if dig +short +timeout=2 google.com @127.0.0.1 > /dev/null 2>&1; then
      STUBBY_OK=true
      break
    fi
    sleep 1
  done

  if [ "$STUBBY_OK" = true ]; then
    # Переключаем resolv.conf на stubby
    cat > /etc/resolv.conf << 'EOF'
nameserver 127.0.0.1
EOF
    # Защищаем от перезаписи DHCP-клиентом
    chattr +i /etc/resolv.conf 2>/dev/null || true
    info "DNS-over-TLS включён через stubby (Cloudflare + Quad9)"
    info "Проверка: dig google.com @127.0.0.1"
  else
    warn "stubby не ответил вовремя — переключаю resolv.conf вручную"
    warn "Если DNS не работает: echo nameserver 127.0.0.1 > /etc/resolv.conf"
    # Переключаем всё равно — stubby скорее всего поднимется чуть позже
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf 2>/dev/null || true
    warn "Проверьте вручную: dig google.com @127.0.0.1"
  fi
}
# ──────────────────────────────────────────────────────────────────
# 5. СМЕНА ПОРТА SSH
#
#    Перенос SSH на нестандартный порт — простейшая и очень
#    эффективная защита от автоматических сканеров (shodan, masscan,
#    и т.д.), которые сканируют только порт 22.
#
#    Что делает функция:
#    • Генерирует случайный порт в диапазоне 49152–65535
#      (ephemeral range — не занят системными сервисами)
#    • Открывает новый порт в UFW ДО смены (чтобы не потерять доступ)
#    • Меняет порт в /etc/ssh/sshd_config
#    • Перезапускает sshd
#    • Закрывает старый порт 22 в UFW
#    • Выводит новый порт и готовую команду подключения
# ──────────────────────────────────────────────────────────────────
change_ssh_port() {
  info "Смена порта SSH..."

  SSHD_CONFIG="/etc/ssh/sshd_config"
  [ -f "$SSHD_CONFIG" ] || error "Файл $SSHD_CONFIG не найден"

  # Определяем текущий порт
  CURRENT_PORT=$(grep -E "^Port " "$SSHD_CONFIG" | awk '{print $2}' | head -1)
  CURRENT_PORT=${CURRENT_PORT:-22}

  # Генерируем случайный порт в диапазоне 49152–65535
  # (IANA "dynamic/private ports" — не зарезервированы системой)
  while true; do
    NEW_PORT=$(shuf -i 49152-65535 -n 1)
    # Проверяем что порт не занят
    if ! ss -tuln | grep -q ":${NEW_PORT} "; then
      break
    fi
  done

  echo ""
  echo -e "${YELLOW}  Текущий порт SSH : ${CURRENT_PORT}${NC}"
  echo -e "${GREEN}  Новый порт SSH   : ${NEW_PORT}${NC}"
  echo ""
  warn "Скрипт откроет новый порт в UFW ДО перезапуска sshd."
  warn "Текущая сессия останется активной."
  echo ""
  read -r -p "  Продолжить? [y/N]: " CONFIRM
  [[ "${CONFIRM,,}" == "y" ]] || { info "Смена порта отменена"; return; }

  # 1. Открываем новый порт в UFW заранее — на случай ошибок не теряем доступ
  if command -v ufw &>/dev/null; then
    ufw allow "${NEW_PORT}/tcp" comment 'SSH new port' > /dev/null
    info "UFW: порт ${NEW_PORT}/tcp открыт"
  fi

  # 2. Меняем порт в sshd_config
  #    Заменяем существующую строку Port или добавляем новую
  if grep -qE "^Port " "$SSHD_CONFIG"; then
    sed -i "s/^Port .*/Port ${NEW_PORT}/" "$SSHD_CONFIG"
  elif grep -qE "^#Port " "$SSHD_CONFIG"; then
    sed -i "s/^#Port .*/Port ${NEW_PORT}/" "$SSHD_CONFIG"
  else
    echo "Port ${NEW_PORT}" >> "$SSHD_CONFIG"
  fi

  # 3. Проверяем конфиг перед перезапуском
  if ! sshd -t 2>/dev/null; then
    error "Ошибка в конфиге sshd — откатываем изменения"
    sed -i "s/^Port .*/Port ${CURRENT_PORT}/" "$SSHD_CONFIG"
    ufw delete allow "${NEW_PORT}/tcp" > /dev/null 2>&1 || true
    return 1
  fi

  # 4. Перезапускаем sshd
  systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null || \
    error "Не удалось перезапустить sshd"

  # 5. Закрываем старый порт 22 в UFW (если он был открыт)
  if command -v ufw &>/dev/null; then
    if ufw status | grep -qE "^22/tcp|^22 "; then
      ufw delete allow 22/tcp > /dev/null 2>&1 || true
      ufw delete allow 22    > /dev/null 2>&1 || true
      info "UFW: старый порт 22 закрыт"
    fi
    ufw reload > /dev/null 2>&1 || true
  fi

  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║         SSH порт успешно изменён!                ║${NC}"
  echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
  echo -e "${GREEN}║  Новый порт : ${YELLOW}${NEW_PORT}${GREEN}                              ║${NC}"
  echo -e "${GREEN}║  Подключение:                                    ║${NC}"
  echo -e "${GREEN}║  ${YELLOW}ssh -p ${NEW_PORT} user@YOUR_SERVER_IP${GREEN}           ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
  echo ""
  warn "Сохраните новый порт! Текущая сессия ещё активна на порту ${CURRENT_PORT}"
  warn "Откройте НОВОЕ окно терминала и проверьте подключение на порту ${NEW_PORT}"
  warn "Только после успешной проверки закройте эту сессию."
  echo ""
}

# ──────────────────────────────────────────────────────────────────
# 6. АВТОЗАПУСК: systemd сервис
#    Запускается ПОСЛЕ Docker чтобы не мешать его правилам iptables.
# ──────────────────────────────────────────────────────────────────
install_service() {
  info "Устанавливаю systemd сервис для автозапуска..."

  cat > /etc/systemd/system/rkn-protect.service << 'EOF'
[Unit]
Description=RKN Protection — TTL + sysctl (Remnawave compatible)
After=network.target docker.service nftables.service
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c '\
  sysctl -p /etc/sysctl.d/99-rkn-protect.conf > /dev/null && \
  nft -f /etc/nftables.d/rkn-protect.nft'
ExecStop=/bin/bash -c 'nft delete table inet rkn_protect 2>/dev/null || true'
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable rkn-protect.service > /dev/null
  info "Сервис rkn-protect.service установлен и включён"
}

# ──────────────────────────────────────────────────────────────────
# 7. FAIL2BAN — защита от SSH брутфорса
#
#    Fail2ban читает /var/log/auth.log, находит повторяющиеся
#    неудачные попытки входа и временно банит IP через UFW/iptables.
#
#    Настройки (выбраны под реальные атаки, не параноя):
#    • 5 неудачных попыток за 10 минут → бан на 1 час
#    • После 3 банов — бан на 24 часа (recidive jail)
#    • Игнорирует localhost и подсети 192.168.x.x / 10.x.x.x
#    • Автоматически подхватывает нестандартный порт SSH
#    • Логирует все баны в /var/log/fail2ban.log
# ──────────────────────────────────────────────────────────────────
configure_fail2ban() {
  info "Устанавливаю и настраиваю Fail2ban..."

  # Устанавливаем если не установлен
  if ! command -v fail2ban-client &>/dev/null; then
    apt-get update -qq
    apt-get install -y fail2ban > /dev/null
    info "Fail2ban установлен"
  else
    info "Fail2ban уже установлен"
  fi

  # Определяем текущий порт SSH из sshd_config
  SSHD_CONFIG="/etc/ssh/sshd_config"
  SSH_PORT=$(grep -E "^Port " "$SSHD_CONFIG" 2>/dev/null | awk '{print $2}' | head -1)
  SSH_PORT=${SSH_PORT:-22}

  info "Обнаружен SSH порт: ${SSH_PORT}"

  # Определяем бэкенд в зависимости от наличия systemd-journald
  if systemctl is-active --quiet systemd-journald 2>/dev/null; then
    F2B_BACKEND="systemd"
    F2B_LOGPATH=""   # journald не требует logpath
  else
    F2B_BACKEND="auto"
    F2B_LOGPATH='logpath = /var/log/auth.log'
  fi

  # Создаём jail.local — он имеет приоритет над jail.conf
  # и не перезаписывается при обновлении пакета
  cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Игнорируем локальные адреса и приватные сети
ignoreip = 127.0.0.1/8 ::1 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16

# Окно наблюдения: 10 минут
findtime  = 600

# Порог: 5 неудачных попыток
maxretry  = 5

# Бан: 1 час
bantime   = 3600

# Бэкенд получения логов
backend = ${F2B_BACKEND}

# Уведомления по email (опционально — закомментировано)
# destemail = root@localhost
# sender    = fail2ban@localhost
# mta       = sendmail
# action    = %(action_mwl)s

[sshd]
enabled  = true
port     = ${SSH_PORT}
filter   = sshd
${F2B_LOGPATH}
maxretry = 5
bantime  = 3600
findtime = 600

# Recidive jail: если IP получил бан 3+ раз за сутки — баним на 24 часа
# Это отсекает упорные ботнеты
[recidive]
enabled  = true
filter   = recidive
logpath  = /var/log/fail2ban.log
action   = %(action_)s
bantime  = 86400
findtime = 86400
maxretry = 3
EOF

  # Убеждаемся что фильтр sshd существует (на всех дистрибутивах есть)
  if [ ! -f /etc/fail2ban/filter.d/sshd.conf ]; then
    warn "Фильтр sshd.conf не найден — возможно нестандартная установка"
  fi

  # Включаем и перезапускаем сервис
  systemctl enable fail2ban  > /dev/null
  systemctl restart fail2ban

  # Даём сервису секунду подняться
  sleep 2

  # Проверяем статус
  if fail2ban-client status sshd &>/dev/null; then
    BANNED_NOW=$(fail2ban-client status sshd | grep "Banned IP" | awk -F: '{print $2}' | xargs)
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║        Fail2ban успешно настроен!                ║${NC}"
    echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
    echo -e "${GREEN}║  SSH порт под защитой : ${YELLOW}${SSH_PORT}${NC}"
    echo -e "${GREEN}║  Порог срабатывания   : ${YELLOW}5 попыток за 10 мин${NC}"
    echo -e "${GREEN}║  Бан                  : ${YELLOW}1 час${NC}"
    echo -e "${GREEN}║  Повторный бан        : ${YELLOW}24 часа (recidive)${NC}"
    echo -e "${GREEN}║  Забанено сейчас      : ${YELLOW}${BANNED_NOW:-нет}${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Полезные команды:"
    echo "  fail2ban-client status sshd       — текущие баны"
    echo "  fail2ban-client set sshd unbanip <IP>  — разбанить IP"
    echo "  tail -f /var/log/fail2ban.log     — живой лог банов"
    echo ""
  else
    warn "Fail2ban запущен, но статус sshd jail недоступен — проверьте: fail2ban-client status"
  fi
}

# ──────────────────────────────────────────────────────────────────
# ГЛАВНОЕ МЕНЮ
# ──────────────────────────────────────────────────────────────────
echo ""
echo "============================================="
echo " RKN Protect — совместимо с Remnawave"
echo " VLESS + XTLS-Reality"
echo "============================================="
echo ""
echo "Модули защиты:"
echo "  1) sysctl hardening (совместимо с BBR)"
echo "  2) nftables — TTL=128 + ICMP фильтрация"
echo "  3) Лимиты fd для Xray (много клиентов)"
echo "  4) DNS-over-TLS (systemd-resolved)"
echo "  5) Fail2ban — защита от SSH брутфорса"
echo "  6) Сменить порт SSH (рандомный 49152–65535)"
echo "  7) Установить всё (1–5) + автозапуск"
echo ""
read -r -p "Ваш выбор [1-7, Enter=7]: " CHOICE

case "${CHOICE:-7}" in
  1) apply_sysctl ;;
  2) apply_nftables ;;
  3) apply_fd_limits ;;
  4) configure_dot ;;
  5) configure_fail2ban ;;
  6) change_ssh_port ;;
  7|"")
    apply_sysctl
    apply_nftables
    apply_fd_limits
    configure_dot
    configure_fail2ban
    install_service
    echo ""
    read -r -p "  Сменить порт SSH сейчас? [y/N]: " SSH_NOW
    [[ "${SSH_NOW,,}" == "y" ]] && change_ssh_port
    ;;
  *) error "Неверный выбор" ;;
esac

echo ""
info "Готово!"
echo ""
echo "  Проверка:"
echo "  nft list table inet rkn_protect   — активные правила nftables"
echo "  resolvectl status                 — статус DNS-over-TLS"
echo "  sysctl net.ipv4.tcp_rfc1337       — должно быть = 1"
echo "  curl -s https://ipleak.net/json/  — проверка утечек"
echo ""
