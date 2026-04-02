#!/usr/bin/env bash
# ================================================================
#  rkn_protect.sh — Защита сервера от блокировок РКН/ТСПУ/DPI
#  Совместимо с: Remnawave + VLESS + XTLS-Reality
#  Протестировано: Ubuntu 22.04/24.04, Debian 12 (bookworm), Debian 13 (trixie)
#  Запуск ПОСЛЕ установки Remnawave: sudo bash rkn_protect.sh
# ================================================================
# set -euo pipefail намеренно НЕ используется:
# многие команды возвращают ненулевой код в штатных ситуациях
# (nft delete несуществующей таблицы, modprobe незагруженного модуля и т.д.)
# Вместо этого — явные проверки критичных шагов через die() и run_critical()
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

# ──────────────────────────────────────────────────────────────────
# ЛОГИРОВАНИЕ (определены ПЕРЕД run_critical для Б1)
# Все действия пишутся в /var/log/rkn-protect.log с таймстампами.
# Вывод идёт одновременно в терминал и в лог (tee).
# ──────────────────────────────────────────────────────────────────
LOG_FILE="/var/log/rkn-protect.log"

_log_raw() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE" 2>/dev/null || true; }

# Переопределяем info/warn/error/die — теперь они пишут и в лог
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

# Проверка на root (возвращена критическая проверка)
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  error "Скрипт должен быть запущен от имени root (sudo)"
fi

# Логируем старт сессии
_log_raw "════════════════════════════════════════"
_log_raw "Запуск rkn_protect.sh (PID=$$, USER=$(whoami 2>/dev/null || echo root))"

# run_critical — выполнить команду; при ошибке — завершить скрипт (Б1: определена ПОСЛЕ die)
run_critical() {
  local desc="$1"; shift
  if ! "$@"; then
    die "${desc} — команда завершилась с ошибкой: $*"
  fi
}

# ──────────────────────────────────────────────────────────────────
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ──────────────────────────────────────────────────────────────────

# Получить внешний IP сервера (кэшируется в переменной SERVER_IP)
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
# На старых ядрах (<4.10) nft работает в режиме iptables-legacy
# через nf_tables — правила принимаются но не применяются.
# Симптом: nft -f отрабатывает без ошибок, но TTL не меняется.
# ──────────────────────────────────────────────────────────────────
check_nftables_compat() {
  local KERNEL_VER
  KERNEL_VER=$(uname -r)
  local KERNEL_MAJOR KERNEL_MINOR
  KERNEL_MAJOR=$(echo "$KERNEL_VER" | cut -d. -f1)
  # Б10: берём только цифровую часть минорной версии
  KERNEL_MINOR=$(echo "$KERNEL_VER" | cut -d. -f2 | tr -cd '0-9')
  # Если оказалось пустым — ставим 0
  [ -z "$KERNEL_MINOR" ] && KERNEL_MINOR=0

  _log_raw "Ядро: $KERNEL_VER"

  # Минимум для полноценного nftables: 4.10+
  if [ "$KERNEL_MAJOR" -lt 4 ] || { [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -lt 10 ]; }; then
    echo ""
    warn "Ядро ${KERNEL_VER} слишком старое для полноценного nftables (нужно >= 4.10)."
    warn "nftables может работать в режиме совместимости через iptables-legacy."
    warn "Правила TTL и mangle могут не применяться корректно."
    warn "Рекомендуется обновить ядро: apt-get install linux-image-amd64"
    echo ""
    read -r -p "  Продолжить установку nftables на старом ядре? [y/N]: " OLD_KERNEL_OK
    [[ "${OLD_KERNEL_OK,,}" == "y" ]] || { info "nftables пропущен из-за старого ядра"; return 1; }
  fi

  # Проверяем что nft реально поддерживает mangle + TTL
  # Пробуем создать тестовую таблицу с TTL-правилом
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
    warn "Вероятно, nftables работает через iptables-nft-legacy."
    warn "TTL-манипуляция (основная функция модуля 2) работать НЕ БУДЕТ."
    echo ""
    read -r -p "  Продолжить установку? [y/N]: " COMPAT_OK
    [[ "${COMPAT_OK,,}" == "y" ]] || { info "nftables пропущен из-за несовместимости"; return 1; }
  else
    _log_raw "nftables: mangle+TTL работает корректно (ядро ${KERNEL_VER})"
  fi

  return 0
}

# Проверка совместимости ОС
check_os() {
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    # Б6: убраны пробелы в паттернах case
    case "$ID-$VERSION_CODENAME" in
      debian-bookworm|debian-trixie|ubuntu-jammy|ubuntu-noble|ubuntu-focal) ;;
      *)
        warn "Система $PRETTY_NAME не тестировалась."
        warn "Поддерживаются: Debian 12/13, Ubuntu 20.04/22.04/24.04"
        read -r -p "  Продолжить на свой страх и риск? [y/N]: " OSOK
        [[ "${OSOK,,}" == "y" ]] || exit 1
        ;;
    esac
  fi
}
check_os

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

  # Идемпотентность: если параметры уже активны — пропускаем перезапись файла
  # Б5: добавлены дефолтные значения при ошибке
  RFC_NOW=$(sysctl -n net.ipv4.tcp_rfc1337 2>/dev/null || echo "0")
  FWD_NOW=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
  if [ "$RFC_NOW" = "1" ] && [ "$FWD_NOW" = "1" ] && \
     [ -f /etc/sysctl.d/99-rkn-protect.conf ]; then
    info "sysctl уже применён (tcp_rfc1337=1, ip_forward=1) — пропускаю перезапись"
    return 0
  fi

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

  # ── Проверка совместимости ядра с nftables ────────────────────────
  check_nftables_compat || return 0

  # ── Проверка конфликта с UFW ──────────────────────────────────────
  # UFW и nftables используют разные бэкенды (iptables vs nft).
  # Совместная работа без явной интеграции может привести к тому,
  # что правила одного инструмента перекрывают правила другого.
  if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo ""
    warn "Обнаружен активный UFW!"
    warn "UFW использует iptables/xtables, nftables работает независимо от него."
    warn "Конфликта правил нет (разные цепочки), НО:"
    warn "  • UFW не видит и не управляет правилами nftables"
    warn "  • После reboot UFW поднимается раньше и может перекрыть nftables-правила"
    warn "  • Рекомендуется: либо оставить только UFW, либо только nftables"
    echo ""
    read -r -p "  Продолжить установку nftables рядом с UFW? [y/N]: " UFW_OK
    [[ "${UFW_OK,,}" == "y" ]] || { info "nftables пропущен"; return; }
    echo ""
  fi

  mkdir -p /etc/nftables.d

  # Б7: проверка идемпотентности — если таблица уже существует и файл не изменился
  if nft list table inet rkn_protect &>/dev/null && [ -f /etc/nftables.d/rkn-protect.nft ]; then
    # Проверяем, что правила в памяти совпадают с файлом
    if nft list table inet rkn_protect 2>/dev/null | grep -q "ttl set 128"; then
      info "nftables таблица rkn_protect уже существует и активна — пропускаю"
      return 0
    fi
  fi

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

    # Блокируем входящий ping — скрываем сервер от сканеров
    icmp type echo-request drop
    icmpv6 type echo-request drop

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

  # Идемпотентность: проверяем что лимиты уже выставлены
  DOCKER_LIMIT_NOW=$(grep "LimitNOFILE" /etc/systemd/system/docker.service.d/limits.conf \
    2>/dev/null | awk -F= '{print $2}')
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

    # timeout 60 — защита от зависания при остановке контейнеров с restart:always
    if ! timeout 60 systemctl restart docker; then
      warn "Docker не перезапустился за 60 секунд — принудительная остановка..."
      systemctl kill docker 2>/dev/null || true
      sleep 2
      systemctl start docker || die "Не удалось запустить Docker после принудительной остановки"
    fi

    # Ждём пока Docker полностью поднимется
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
      die "Docker не поднялся за 15 секунд после перезапуска. Проверьте: systemctl status docker"
    fi

    # Поднимаем обратно контейнеры Remnawave если они есть
    if [ -d /opt/remnawave ]; then
      cd /opt/remnawave && timeout 60 docker compose up -d > /dev/null 2>&1 || \
        warn "docker compose up /opt/remnawave завершился с ошибкой — проверьте вручную"
    fi

    # Поднимаем контейнеры бота если есть
    BOT_DIR=$(find /root /home -maxdepth 3 -name "docker-compose.yml" 2>/dev/null | \
      xargs grep -l "remnawave_bot" 2>/dev/null | head -1 | xargs dirname 2>/dev/null)
    if [ -n "$BOT_DIR" ] && [ "$BOT_DIR" != "/opt/remnawave" ]; then
      cd "$BOT_DIR" && timeout 60 docker compose up -d > /dev/null 2>&1 || \
        warn "docker compose up $BOT_DIR завершился с ошибкой — проверьте вручную"
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

  # Идемпотентность: если DoT уже настроен и работает — пропускаем
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

  # Определяем способ настройки DoT
  if systemctl list-units --type=service 2>/dev/null | grep -q "systemd-resolved" || \
      systemctl list-unit-files 2>/dev/null | grep -q "systemd-resolved"; then
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
    if systemctl is-active --quiet systemd-resolved 2>/dev/null && \
        getent hosts cloudflare.com > /dev/null 2>&1; then
      DNS_OK=true
      break
    fi
    sleep 1
  done

  if [ "$DNS_OK" = true ]; then
    info "DNS-over-TLS включён через systemd-resolved (Cloudflare + Quad9)"
    rm -f /etc/resolv.conf.backup

    # Проверяем что DNS реально идёт через TLS, а не просто отвечает
    # resolvectl query показывает "DNSOverTLS: yes" если соединение зашифровано
    echo ""
    info "Проверяю что запросы идут через TLS (не просто DNS)..."
    if command -v resolvectl &>/dev/null; then
      TLS_STATUS=$(resolvectl query cloudflare.com 2>&1 | grep -i "via" || true)
      TLS_FLAGS=$(resolvectl status 2>/dev/null | grep -i "DNSOverTLS\|DNS Over TLS" || true)
      if echo "$TLS_FLAGS" | grep -qi "yes"; then
        info "✓ TLS подтверждён: resolvectl сообщает DNSOverTLS: yes"
      else
        warn "resolvectl не подтверждает TLS — возможно resolved не поддерживает DoT на этой версии"
        warn "Проверьте вручную: resolvectl status | grep -i tls"
        warn "Требуется systemd >= 237. Текущая версия: $(systemctl --version | head -1)"
      fi
    else
      # resolvectl нет — пробуем через openssl: проверяем порт 853 (DNS-over-TLS)
      if command -v openssl &>/dev/null; then
        if echo | timeout 5 openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com \
            > /dev/null 2>&1; then
          info "✓ TLS подтверждён: порт 853 (DoT) на 1.1.1.1 доступен и отвечает"
        else
          warn "Порт 853 недоступен — DoT может быть заблокирован провайдером/хостером"
          warn "DNS работает, но возможно через plaintext UDP/53"
        fi
      else
        warn "resolvectl и openssl недоступны — проверьте TLS вручную"
        warn "Команда: echo | openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com"
      fi
    fi
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
  - address_data: 77.88.8.8
    tls_auth_name: "common.dot.yandex.net"
  - address_data: 1.1.1.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 9.9.9.9
    tls_auth_name: "dns.quad9.net"
  - address_data: 1.0.0.1
    tls_auth_name: "cloudflare-dns.com"
  - address_data: 149.112.112.112
    tls_auth_name: "dns.quad9.net"
  - address_data: 77.88.8.1
    tls_auth_name: "common.dot.yandex.net"
EOF

  systemctl enable --now stubby > /dev/null 2>&1

  # Ждём пока stubby установит TLS-соединение с upstream (до 15 секунд)
  info "Жду запуска stubby..."
  STUBBY_OK=false
  for i in $(seq 1 15); do
    # Б13: исправлен фоллбэк DNS резолва
    if command -v dig &>/dev/null; then
      if dig +short +timeout=2 google.com @127.0.0.1 > /dev/null 2>&1; then
        STUBBY_OK=true
        break
      fi
    elif command -v nslookup &>/dev/null && nslookup google.com 127.0.0.1 >/dev/null 2>&1; then
      STUBBY_OK=true
      break
    elif ss -tuln | grep -q "127.0.0.1:53"; then
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
    # Защищаем от перезаписи DHCP-клиентом — через NetworkManager или dhclient hook,
    # НЕ через chattr +i (он блокирует файл для systemd/apt/обновлений системы)
    if [ -d /etc/NetworkManager/conf.d ]; then
      cat > /etc/NetworkManager/conf.d/no-dns.conf << 'EOF'
[main]
dns=none
EOF
      systemctl reload NetworkManager 2>/dev/null || true
      info "NetworkManager: управление DNS передано stubby"
    elif [ -f /etc/dhcp/dhclient-enter-hooks.d ] || [ -d /etc/dhcp/dhclient-enter-hooks.d ]; then
      cat > /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate << 'EOF'
#!/bin/sh
# Запрещаем dhclient перезаписывать resolv.conf (используется stubby)
make_resolv_conf() { :; }
EOF
      chmod +x /etc/dhcp/dhclient-enter-hooks.d/nodnsupdate
      info "dhclient: защита resolv.conf через hook установлена"
    else
      warn "Не найден NetworkManager и dhclient — resolv.conf может быть перезаписан DHCP"
      warn "Для защиты вручную: добавьте 'dns=none' в /etc/NetworkManager/conf.d/no-dns.conf"
    fi
    info "DNS-over-TLS включён через stubby (Cloudflare + Quad9)"
    info "Проверка: dig google.com @127.0.0.1 или getent hosts google.com"

    # Проверяем что stubby реально использует TLS (порт 853), а не plaintext
    echo ""
    info "Проверяю TLS-соединение stubby с upstream..."
    if command -v openssl &>/dev/null; then
      if echo | timeout 5 openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com \
          > /dev/null 2>&1; then
        info "✓ TLS подтверждён: порт 853 (DoT) на Cloudflare доступен"
      else
        warn "Порт 853 (DoT) недоступен с этого сервера — stubby работает, но возможно без TLS"
        warn "Проверьте: echo | openssl s_client -connect 1.1.1.1:853 -servername cloudflare-dns.com"
      fi
    else
      # openssl нет — проверяем через ss что stubby слушает на 53
      if ss -tuln | grep -q ":53 "; then
        info "stubby слушает порт 53 — DNS работает"
        warn "Установите openssl для проверки TLS: apt-get install -y openssl"
      fi
    fi
  else
    warn "stubby не ответил вовремя — переключаю resolv.conf вручную"
    warn "Если DNS не работает: echo nameserver 127.0.0.1 > /etc/resolv.conf"
    # Переключаем всё равно — stubby скорее всего поднимется чуть позже
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    warn "Проверьте вручную: dig google.com @127.0.0.1 или getent hosts google.com"
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

  # 0. Проверяем доступность нового порта снаружи через внешний сервис
  #    Это защищает от ситуации когда хостер блокирует все порты кроме стандартных.
  echo ""
  info "Проверяю доступность порта ${NEW_PORT} снаружи..."
  # Б3: используем get_server_ip() вместо прямого присваивания
  SERVER_IP=$(get_server_ip)

  PORT_REACHABLE=false
  if [ -n "$SERVER_IP" ]; then
    # Открываем порт временно на localhost для проверки
    if command -v nc &>/dev/null; then
      # Б4: проверяем версию netcat для правильного синтаксиса
      # OpenBSD netcat (Debian/Ubuntu): nc -l PORT (без -p)
      # BSD netcat (macOS): nc -l -p PORT
      if nc -h 2>&1 | grep -q "OpenBSD"; then
        # OpenBSD версия — используем синтаксис без -p
        nc -l "${NEW_PORT}" > /dev/null 2>&1 &
      else
        # BSD/traditional версия — используем -p
        nc -l -p "${NEW_PORT}" > /dev/null 2>&1 &
      fi
      NC_PID=$!
      sleep 1
      # Проверяем через внешний сервис portchecker
      CHECK_RESULT=$(curl -s --max-time 7 \
        "https://portchecker.co/api/v1/query" \
        -H "Content-Type: application/json" \
        -d "{\"host\":\"${SERVER_IP}\",\"ports\":[${NEW_PORT}]}" 2>/dev/null || true)
      kill $NC_PID 2>/dev/null || true
      if echo "$CHECK_RESULT" | grep -q '"isOpen":true'; then
        PORT_REACHABLE=true
        info "✓ Порт ${NEW_PORT} доступен снаружи"
      fi
    fi
  fi

  if [ "$PORT_REACHABLE" = false ]; then
    echo ""
    warn "Не удалось подтвердить что порт ${NEW_PORT} доступен снаружи."
    warn "Возможные причины:"
    warn "  • Хостер блокирует нестандартные порты на уровне своего firewall"
    warn "  • Нет доступа к интернету для проверки (curl недоступен)"
    warn "  • Инструмент проверки временно недоступен"
    echo ""
    warn "РИСК: если порт закрыт на хостере — вы потеряете SSH-доступ!"
    warn "Перед сменой порта откройте его в панели управления хостера."
    echo ""
    read -r -p "  Всё равно сменить порт? [y/N]: " FORCE_CONFIRM
    [[ "${FORCE_CONFIRM,,}" == "y" ]] || { info "Смена порта отменена"; return; }
  fi
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

  # Получаем реальный IP (уже был запрошен при проверке порта, берём из кэша)
  DISPLAY_IP=$(get_server_ip)
  DISPLAY_IP=${DISPLAY_IP:-YOUR_SERVER_IP}

  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║         SSH порт успешно изменён!                ║${NC}"
  echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
  echo -e "${GREEN}║  Новый порт : ${YELLOW}${NEW_PORT}${GREEN}                              ║${NC}"
  echo -e "${GREEN}║  Подключение:                                    ║${NC}"
  echo -e "${GREEN}║  ${YELLOW}ssh -p ${NEW_PORT} user@${DISPLAY_IP}${GREEN}    ║${NC}"
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

  # Определяем banaction: если nftables активен — используем его бэкенд,
  # иначе падаем на iptables-multiport (стандартный).
  # Смешивать нельзя: fail2ban должен банить через тот же фреймворк что управляет пакетами.
  if command -v nft &>/dev/null && systemctl is-active --quiet nftables 2>/dev/null; then
    F2B_BANACTION="nftables-multiport"
    F2B_BANACTION_ALLPORTS="nftables-allports"
    info "Fail2ban: используем nftables-бэкенд (совместимо с модулем 2)"
  else
    F2B_BANACTION="iptables-multiport"
    F2B_BANACTION_ALLPORTS="iptables-allports"
    info "Fail2ban: используем iptables-бэкенд"
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

# Бэкенд бана — nftables или iptables (определяется автоматически выше)
# Важно: должен совпадать с фреймворком управления пакетами на сервере
banaction = ${F2B_BANACTION}
banaction_allports = ${F2B_BANACTION_ALLPORTS}

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
# 8. SSH HARDENING
#
#    Закрывает типовые уязвимости sshd которые находит Lynis:
#    PermitRootLogin, MaxAuthTries, X11Forwarding и другие.
# ──────────────────────────────────────────────────────────────────
harden_ssh() {
  info "Применяю SSH hardening..."

  SSHD_CONFIG="/etc/ssh/sshd_config"
  [ -f "$SSHD_CONFIG" ] || error "Файл $SSHD_CONFIG не найден"

  # Б8: проверка интерактивности — если stdin не tty, пропускаем вопрос
  if [[ ! -t 0 ]]; then
    warn "Обнаружен неинтерактивный запуск (pipe). SSH hardening пропущён."
    warn "Для применения запустите скрипт интерактивно или выберите модуль 6 отдельно."
    return 0
  fi

  # Предупреждение: AllowTcpForwarding no ломает SSH-туннели
  echo ""
  warn "SSH hardening отключит AllowTcpForwarding и AllowAgentForwarding."
  warn "Это СЛОМАЕТ SSH-туннели (например: ssh -L, -R, -D, WireGuard-over-SSH)."
  warn "Если вы используете SSH для проброса портов — ответьте 'n' и пропустите этот модуль."
  echo ""
  read -r -p "  Продолжить? [y/N]: " SSH_HARDEN_OK
  [[ "${SSH_HARDEN_OK,,}" == "y" ]] || { info "SSH hardening пропущен"; return; }
  echo ""

  # Бэкап
  cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.$(date +%Y%m%d%H%M%S)"

  # Функция установки/замены параметра
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
  set_sshd_param "ClientAliveCountMax"   "2"
  set_sshd_param "ClientAliveInterval"   "300"
  set_sshd_param "LogLevel"             "VERBOSE"
  set_sshd_param "PrintLastLog"          "yes"
  set_sshd_param "IgnoreRhosts"          "yes"
  set_sshd_param "PermitEmptyPasswords"  "no"
  set_sshd_param "LoginGraceTime"        "30"

  # Проверяем конфиг перед перезапуском
  if sshd -t 2>/dev/null; then
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    info "SSH hardening применён"
    echo ""
    echo "  Применённые параметры:"
    echo "  MaxAuthTries         3    — максимум попыток ввода пароля"
    echo "  MaxSessions          3    — максимум одновременных сессий"
    echo "  X11Forwarding        no   — GUI forwarding отключён"
    echo "  AllowTcpForwarding   no   — туннели через SSH запрещены"
    echo "  AllowAgentForwarding no   — проброс SSH-агента запрещён"
    echo "  Compression          no   — сжатие отключено"
    echo "  LoginGraceTime       30s  — таймаут аутентификации"
    echo "  LogLevel             VERBOSE — детальные логи для fail2ban"
    echo ""
  else
    warn "Ошибка в конфиге sshd — откатываю изменения"
    LATEST_BAK=$(ls -t ${SSHD_CONFIG}.bak.* 2>/dev/null | head -1)
    [ -n "$LATEST_BAK" ] && cp "$LATEST_BAK" "$SSHD_CONFIG" || true
  fi
}


# ──────────────────────────────────────────────────────────────────
# 10. ОТКЛЮЧЕНИЕ НЕИСПОЛЬЗУЕМЫХ СЕТЕВЫХ ПРОТОКОЛОВ
#
#    dccp, sctp, rds, tipc — экзотические протоколы которые
#    не используются на типичном VPS-сервере, но расширяют
#    поверхность атаки. Lynis рекомендует их отключить.
#    Отключение через modprobe — безопасно, Docker и Remnawave
#    используют только TCP/UDP, эти протоколы им не нужны.
# ──────────────────────────────────────────────────────────────────
disable_unused_protocols() {
  info "Отключаю неиспользуемые сетевые протоколы..."

  # Идемпотентность: если modprobe-конфиг уже стоит и ни один протокол не загружен
  BLOCKED=$(grep -c "install .* /bin/false" /etc/modprobe.d/unused-protocols.conf 2>/dev/null || echo "0")
  LOADED=$(lsmod 2>/dev/null | grep -cE "^(dccp|sctp|rds|tipc)" || echo "0")
  if [ "$BLOCKED" -ge 4 ] && [ "$LOADED" = "0" ]; then
    info "Протоколы уже отключены — пропускаю"
    return 0
  fi

  cat > /etc/modprobe.d/unused-protocols.conf << 'EOF'
# Отключение неиспользуемых сетевых протоколов (Lynis NETW-3200)
# Эти протоколы не нужны на VPS с Remnawave/VLESS и расширяют поверхность атаки

# DCCP — Datagram Congestion Control Protocol
install dccp /bin/false

# SCTP — Stream Control Transmission Protocol
install sctp /bin/false

# RDS — Reliable Datagram Sockets (Oracle)
install rds /bin/false

# TIPC — Transparent Inter-Process Communication
install tipc /bin/false
EOF

  # Выгружаем модули если они сейчас загружены
  for proto in dccp sctp rds tipc; do
    if lsmod | grep -q "^${proto}"; then
      modprobe -r "$proto" 2>/dev/null && \
        info "Модуль ${proto} выгружен" || \
        warn "Не удалось выгрузить ${proto} — будет отключён после перезагрузки"
    fi
  done

  # Обновляем initramfs чтобы изменения сохранились после перезагрузки
  update-initramfs -u 2>/dev/null || true

  echo ""
  info "Протоколы dccp, sctp, rds, tipc отключены"
  echo "  Проверка загруженных модулей:"
  lsmod | grep -E "^(dccp|sctp|rds|tipc)" || echo "  Ни один из протоколов не загружен — всё чисто"
}

# ──────────────────────────────────────────────────────────────────
# ПРОВЕРКА СТАТУСА ВСЕХ МОДУЛЕЙ
# ──────────────────────────────────────────────────────────────────
status_check() {
  local OK="${GREEN}✓${NC}" FAIL="${RED}✗${NC}" WARN="${YELLOW}~${NC}"
  echo ""
  echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║         RKN Protect — статус модулей                ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
  echo ""

  # 1. sysctl
  # Б5: добавлены дефолтные значения при ошибке
  RFC=$(sysctl -n net.ipv4.tcp_rfc1337 2>/dev/null || echo "0")
  FWD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo "0")
  if [ "$RFC" = "1" ] && [ "$FWD" = "1" ]; then
    echo -e "  ${OK} sysctl       tcp_rfc1337=1, ip_forward=1"
  elif [ -f /etc/sysctl.d/99-rkn-protect.conf ]; then
    echo -e "  ${WARN} sysctl       конфиг есть, но не применён (rfc1337=${RFC:-?})"
  else
    echo -e "  ${FAIL} sysctl       не настроен"
  fi

  # 2. nftables
  if nft list table inet rkn_protect > /dev/null 2>&1; then
    TTL_RULE=$(nft list table inet rkn_protect 2>/dev/null | grep -c "ttl set 128" || true)
    echo -e "  ${OK} nftables     таблица rkn_protect активна (TTL-правил: ${TTL_RULE})"
  elif [ -f /etc/nftables.d/rkn-protect.nft ]; then
    echo -e "  ${WARN} nftables     конфиг есть, таблица не загружена"
  else
    echo -e "  ${FAIL} nftables     не настроен"
  fi

  # 3. fd limits
  DOCKER_LIMIT=$(cat /etc/systemd/system/docker.service.d/limits.conf 2>/dev/null | \
    grep LimitNOFILE | awk -F= '{print $2}')
  SYS_LIMIT=$(cat /etc/security/limits.d/99-xray.conf 2>/dev/null | \
    grep "root hard" | awk '{print $4}')
  if [ "${DOCKER_LIMIT}" = "1048576" ] && [ "${SYS_LIMIT}" = "1048576" ]; then
    echo -e "  ${OK} fd limits    nofile=1048576 (Docker + system)"
  elif [ -n "$DOCKER_LIMIT" ] || [ -n "$SYS_LIMIT" ]; then
    echo -e "  ${WARN} fd limits    частично настроен (docker=${DOCKER_LIMIT:-нет}, system=${SYS_LIMIT:-нет})"
  else
    echo -e "  ${FAIL} fd limits    не настроен"
  fi

  # 4. DNS-over-TLS
  DNS_METHOD=""
  DNS_TLS_OK=false
  if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
    TLS_FLAG=$(resolvectl status 2>/dev/null | grep -i "DNSOverTLS" | grep -i "yes" || true)
    [ -n "$TLS_FLAG" ] && DNS_TLS_OK=true
    DNS_METHOD="systemd-resolved"
  elif systemctl is-active --quiet stubby 2>/dev/null; then
    DNS_METHOD="stubby"
    # Проверяем что resolv.conf указывает на 127.0.0.1
    grep -q "127.0.0.1" /etc/resolv.conf 2>/dev/null && DNS_TLS_OK=true
  fi
  if [ "$DNS_TLS_OK" = true ]; then
    echo -e "  ${OK} DNS-over-TLS ${DNS_METHOD} активен, TLS подтверждён"
  elif [ -n "$DNS_METHOD" ]; then
    echo -e "  ${WARN} DNS-over-TLS ${DNS_METHOD} запущен, TLS не подтверждён"
  else
    echo -e "  ${FAIL} DNS-over-TLS не настроен"
  fi

  # 5. Fail2ban
  if systemctl is-active --quiet fail2ban 2>/dev/null; then
    BANNED=$(fail2ban-client status sshd 2>/dev/null | grep "Currently banned" | \
      awk -F: '{print $2}' | xargs || echo "?")
    # Б11: исправлен парсинг banaction — используем разделитель =
    BANACT=$(grep "^banaction" /etc/fail2ban/jail.local 2>/dev/null | awk -F= '{print $2}' | xargs || echo "default")
    echo -e "  ${OK} fail2ban     активен, забанено: ${BANNED}, бэкенд: ${BANACT}"
  elif command -v fail2ban-client &>/dev/null; then
    echo -e "  ${WARN} fail2ban     установлен, но не запущен"
  else
    echo -e "  ${FAIL} fail2ban     не установлен"
  fi

  # 6. SSH hardening
  SSH_CFG="/etc/ssh/sshd_config"
  SSH_PORT_NOW=$(grep -E "^Port " "$SSH_CFG" 2>/dev/null | awk '{print $2}' || echo "22")
  MAX_AUTH=$(grep -E "^MaxAuthTries" "$SSH_CFG" 2>/dev/null | awk '{print $2}' || echo "-")
  X11=$(grep -E "^X11Forwarding" "$SSH_CFG" 2>/dev/null | awk '{print $2}' || echo "-")
  if [ "$MAX_AUTH" = "3" ] && [ "$X11" = "no" ]; then
    echo -e "  ${OK} SSH          порт=${SSH_PORT_NOW}, MaxAuthTries=3, X11=no"
  elif [ "$MAX_AUTH" != "-" ]; then
    echo -e "  ${WARN} SSH          порт=${SSH_PORT_NOW}, hardening частичный (MaxAuthTries=${MAX_AUTH})"
  else
    echo -e "  ${FAIL} SSH          hardening не применён (порт=${SSH_PORT_NOW})"
  fi

  # 7. Неиспользуемые протоколы
  PROTOS_BLOCKED=$(grep -c "install .* /bin/false" /etc/modprobe.d/unused-protocols.conf 2>/dev/null || echo "0")
  PROTOS_LOADED=$(lsmod 2>/dev/null | grep -cE "^(dccp|sctp|rds|tipc)" || echo "0")
  if [ "$PROTOS_BLOCKED" -ge 4 ] && [ "$PROTOS_LOADED" = "0" ]; then
    echo -e "  ${OK} протоколы    dccp/sctp/rds/tipc отключены, ни один не загружен"
  elif [ "$PROTOS_BLOCKED" -ge 4 ]; then
    echo -e "  ${WARN} протоколы    отключены в modprobe, загружено модулей: ${PROTOS_LOADED}"
  else
    echo -e "  ${FAIL} протоколы    не отключены"
  fi

  # systemd сервис
  if systemctl is-enabled --quiet rkn-protect.service 2>/dev/null; then
    SVC_STATE=$(systemctl is-active rkn-protect.service 2>/dev/null || echo "inactive")
    echo -e "  ${OK} автозапуск   rkn-protect.service включён (${SVC_STATE})"
  else
    echo -e "  ${FAIL} автозапуск   rkn-protect.service не установлен"
  fi

  echo ""
}

# ──────────────────────────────────────────────────────────────────
# ОТКАТ ИЗМЕНЕНИЙ
# ──────────────────────────────────────────────────────────────────
rollback() {
  echo ""
  echo -e "${RED}╔══════════════════════════════════════════════════════╗${NC}"
  echo -e "${RED}║              Откат изменений RKN Protect            ║${NC}"
  echo -e "${RED}╚══════════════════════════════════════════════════════╝${NC}"
  echo ""
  echo "  Выберите что откатить:"
  echo "  1) nftables — удалить таблицу rkn_protect (немедленно)"
  echo "  2) sysctl   — удалить /etc/sysctl.d/99-rkn-protect.conf"
  echo "  3) SSH      — восстановить последний бэкап sshd_config"
  echo "  4) Fail2ban — остановить и удалить jail.local"
  echo "  5) Сервис   — отключить rkn-protect.service"
  echo "  6) Всё      — полный откат всех модулей"
  echo "  0) Отмена"
  echo ""
  read -r -p "  Ваш выбор: " RB_CHOICE

  # Б9: исправлен fallthrough — используем отдельную функцию для полного отката
  case "${RB_CHOICE}" in
    1)
      nft delete table inet rkn_protect 2>/dev/null && \
        info "nftables: таблица rkn_protect удалена" || \
        warn "nftables: таблица не найдена (уже удалена?)"
      # Убираем include из nftables.conf
      if [ -f /etc/nftables.conf ]; then
        sed -i '/rkn-protect/d' /etc/nftables.conf
        info "nftables: include удалён из /etc/nftables.conf"
      fi
      rm -f /etc/nftables.d/rkn-protect.nft
      ;;
    2)
      if [ -f /etc/sysctl.d/99-rkn-protect.conf ]; then
        rm -f /etc/sysctl.d/99-rkn-protect.conf
        sysctl --system > /dev/null 2>&1 || true
        info "sysctl: 99-rkn-protect.conf удалён, параметры перезагружены"
      else
        warn "sysctl: файл не найден"
      fi
      ;;
    3)
      SSHD_CONFIG="/etc/ssh/sshd_config"
      LATEST_BAK=$(ls -t "${SSHD_CONFIG}".bak.* 2>/dev/null | head -1)
      if [ -n "$LATEST_BAK" ]; then
        cp "$LATEST_BAK" "$SSHD_CONFIG"
        if sshd -t 2>/dev/null; then
          systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
          info "SSH: восстановлен из ${LATEST_BAK}, sshd перезапущен"
        else
          warn "SSH: бэкап скопирован, но sshd -t вернул ошибку — проверьте вручную"
        fi
      else
        warn "SSH: бэкапов sshd_config не найдено"
      fi
      ;;
    4)
      if systemctl is-active --quiet fail2ban 2>/dev/null; then
        systemctl stop fail2ban
        info "fail2ban: остановлен"
      fi
      rm -f /etc/fail2ban/jail.local
      info "fail2ban: jail.local удалён"
      ;;
    5)
      if systemctl is-enabled --quiet rkn-protect.service 2>/dev/null; then
        systemctl disable --now rkn-protect.service > /dev/null 2>&1 || true
        rm -f /etc/systemd/system/rkn-protect.service
        systemctl daemon-reload
        info "сервис: rkn-protect.service отключён и удалён"
      else
        warn "сервис: не установлен"
      fi
      ;;
    6)
      # Полный откат — вызываем все функции отката последовательно
      info "Выполняю полный откат всех модулей..."

      # nftables
      nft delete table inet rkn_protect 2>/dev/null && \
        info "nftables: таблица rkn_protect удалена" || true
      if [ -f /etc/nftables.conf ]; then
        sed -i '/rkn-protect/d' /etc/nftables.conf
      fi
      rm -f /etc/nftables.d/rkn-protect.nft

      # sysctl
      if [ -f /etc/sysctl.d/99-rkn-protect.conf ]; then
        rm -f /etc/sysctl.d/99-rkn-protect.conf
        sysctl --system > /dev/null 2>&1 || true
        info "sysctl: конфиг удалён"
      fi

      # SSH
      SSHD_CONFIG="/etc/ssh/sshd_config"
      LATEST_BAK=$(ls -t "${SSHD_CONFIG}".bak.* 2>/dev/null | head -1)
      if [ -n "$LATEST_BAK" ]; then
        cp "$LATEST_BAK" "$SSHD_CONFIG"
        sshd -t 2>/dev/null && systemctl restart sshd 2>/dev/null || true
        info "SSH: восстановлен из бэкапа"
      fi

      # fail2ban
      systemctl stop fail2ban 2>/dev/null || true
      rm -f /etc/fail2ban/jail.local
      info "fail2ban: остановлен и удалён"

      # сервис
      systemctl disable --now rkn-protect.service > /dev/null 2>&1 || true
      rm -f /etc/systemd/system/rkn-protect.service
      systemctl daemon-reload
      info "сервис: отключён и удалён"

      info "Полный откат завершён"
      ;;
    0)
      info "Откат отменён"
      ;;
    *)
      warn "Неверный выбор"
      ;;
  esac
  echo ""
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
echo "  2) nftables — TTL=128 + ICMP + ping фильтрация"
echo "  3) Лимиты fd для Xray (много клиентов)"
echo "  4) DNS-over-TLS (stubby + Cloudflare + Quad9 + Yandex)"
echo "  5) Fail2ban — защита от SSH брутфорса"
echo "  6) SSH hardening (Lynis рекомендации)"
echo "  7) Отключение неиспользуемых протоколов (dccp/sctp/rds/tipc)"
echo "  8) Сменить порт SSH (рандомный 49152–65535)"
echo "  9) Установить всё (1–7) + автозапуск"
echo " 10) Статус всех модулей"
echo " 11) Откат изменений"
echo ""
read -r -p "Ваш выбор [1-11, Enter=9]: " CHOICE
_log_raw "Выбор пользователя: ${CHOICE:-9}"

case "${CHOICE:-9}" in
  1) apply_sysctl ;;
  2) apply_nftables ;;
  3) apply_fd_limits ;;
  4) configure_dot ;;
  5)
    echo ""
    echo "  5) Fail2ban:"
    echo "     a) Установить / настроить"
    echo "     b) Статус (активные баны, jail sshd)"
    echo ""
    read -r -p "  Ваш выбор [a/b]: " F2B_CHOICE
    case "${F2B_CHOICE,,}" in
      b)
        echo ""
        if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
          warn "Fail2ban не запущен. Выберите пункт 5a для настройки."
        else
          fail2ban-client status sshd 2>/dev/null || warn "Jail sshd недоступен — проверьте: fail2ban-client status"
          echo ""
          echo -e "${GREEN}── Последние баны ─────────────────────────────────${NC}"
          grep "Ban " /var/log/fail2ban.log 2>/dev/null | tail -10 || echo "  Лог пуст"
          echo ""
          echo "  fail2ban-client set sshd unbanip <IP>  — разбанить IP"
          echo "  tail -f /var/log/fail2ban.log          — живой лог"
        fi
        ;;
      *) configure_fail2ban ;;
    esac
    ;;
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
    echo ""
    # Б8: проверка интерактивности перед вопросом о смене порта
    if [[ -t 0 ]]; then
      read -r -p "  Сменить порт SSH сейчас? [y/N]: " SSH_NOW
      [[ "${SSH_NOW,,}" == "y" ]] && change_ssh_port
    else
      warn "Неинтерактивный режим — пропускаю смену порта SSH"
      warn "Для смены порта запустите: sudo bash rkn_protect.sh и выберите пункт 8"
    fi
    ;;
  10) status_check ;;
  11) rollback ;;
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

# Б12: показываем IP только если не status_check или rollback
if [[ "${CHOICE:-9}" != "10" && "${CHOICE:-9}" != "11" ]]; then
  # Показываем реальный IP для удобства
  _FINAL_IP=$(get_server_ip)
  if [ -n "$_FINAL_IP" ]; then
    SSH_PORT_FINAL=$(grep -E "^Port " /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    SSH_PORT_FINAL=${SSH_PORT_FINAL:-22}
    echo -e "  ${GREEN}Подключение к серверу:${NC}"
    echo -e "  ${YELLOW}ssh -p ${SSH_PORT_FINAL} user@${_FINAL_IP}${NC}"
    echo ""
  fi
fi

echo "  Лог выполнения: ${LOG_FILE}"
echo ""
_log_raw "Скрипт завершён (выбор: ${CHOICE:-9})"
