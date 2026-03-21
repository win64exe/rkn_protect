# rkn_protect.sh

Скрипт защиты Linux-сервера от блокировок РКН/ТСПУ/DPI.  
Совместим с **Remnawave + VLESS + XTLS-Reality**.

## Что делает

| Модуль | Описание |
|--------|----------|
| **sysctl hardening** | Защита сетевого стека: RST-инъекции, redirects, source routing. Совместимо с BBR |
| **nftables TTL=128** | Имитация Windows-хоста, ICMP фильтрация. Не ломает Docker и ноды Remnawave |
| **Лимиты fd для Xray** | 1 048 576 файловых дескрипторов — для большого числа параллельных VLESS-соединений |
| **DNS-over-TLS** | Шифрованные DNS через Cloudflare + Quad9 via systemd-resolved. Защита от DNS-спуфинга РКН |
| **Fail2ban** | Бан после 5 неудачных SSH-попыток за 10 минут. Recidive jail: 3 бана → 24 часа |
| **Смена порта SSH** | Случайный порт 49152–65535. Автоматически обновляет UFW, не теряет текущую сессию |

## Требования

- Ubuntu 22.04 / 24.04 или Debian 12
- Root доступ
- UFW установлен и активен

## Установка

```bash
curl -o rkn_protect.sh https://raw.githubusercontent.com/win64exe/rkn_protect/main/rkn_protect.sh](https://raw.githubusercontent.com/win64exe/rkn_protect/refs/heads/main/rkn_protect.sh
chmod +x rkn_protect.sh
sudo bash rkn_protect.sh
```

## Использование

```
=============================================
 RKN Protect — совместимо с Remnawave
 VLESS + XTLS-Reality
=============================================

Модули защиты:
  1) sysctl hardening (совместимо с BBR)
  2) nftables — TTL=128 + ICMP фильтрация
  3) Лимиты fd для Xray (много клиентов)
  4) DNS-over-TLS (systemd-resolved)
  5) Fail2ban — защита от SSH брутфорса
  6) Сменить порт SSH (рандомный 49152–65535)
  7) Установить всё (1–5) + автозапуск
```

Выберите `7` для полной установки. В конце скрипт отдельно спросит про смену порта SSH.

## Совместимость с Remnawave

Скрипт специально адаптирован под стек Remnawave:

- `tcp_timestamps = 1` — BBR работает корректно (Remnawave включает BBR при установке)
- RST drop **убран** из nftables — он обрывал соединения между панелью и нодами
- `ip_forward = 1` — Docker и контейнеры маршрутизируют трафик корректно
- TTL=128 применяется в `postrouting` — весь трафик контейнеров тоже получает правильный TTL
- Fail2ban следит только за SSH, не затрагивает VLESS-трафик

## Порядок установки

```bash
# 1. Сначала установите Remnawave
bash install_remnawave.sh

# 2. Затем запустите этот скрипт
sudo bash rkn_protect.sh
```

## Проверка после установки

```bash
# Активные nftables правила
nft list table inet rkn_protect

# Статус DNS-over-TLS
resolvectl status | grep -A5 "DNS Servers"

# Защита от RST-инъекций
sysctl net.ipv4.tcp_rfc1337

# Статус Fail2ban
fail2ban-client status sshd

# Текущий SSH порт
grep "^Port" /etc/ssh/sshd_config
```

## Fail2ban — полезные команды

```bash
# Кто забанен прямо сейчас
fail2ban-client status sshd

# Разбанить конкретный IP
fail2ban-client set sshd unbanip 1.2.3.4

# Живой лог банов
tail -f /var/log/fail2ban.log
```

## Автозапуск

Скрипт устанавливает systemd-сервис `rkn-protect.service` который восстанавливает nftables правила и sysctl после перезагрузки. Запускается после Docker чтобы не конфликтовать с его правилами.

```bash
systemctl status rkn-protect
```

## Лицензия

MIT
