#!/usr/bin/env bash
# Chuẩn bị máy deployer (máy AIO chạy Kolla + chạy scripts/deploy-all.sh) — gọi từ deploy-all.sh,
# LUÔN chạy (không phụ thuộc --from-step), idempotent, chạy lại bao nhiêu lần cũng được.
#
# Gom 3 sự cố thật gặp ở lần dựng 2026-10-10 mà bản thân Terraform/Ansible không tự phát hiện:
#
#  1. THIẾU RAM → OOM. 5 VM OpenStack (3×m1.medium 4 GB + 2×nano-plus 1 GB = 14 GB) + control-plane
#     Kolla (~4-5 GB) vượt 16 GB RAM của máy. Kernel OOM-kill qemu của os-k3s-master, load host vọt 85,
#     k3s agent timeout. Xử lý: bảo đảm có swap ≥ 16 GB (tạm — nâng RAM vẫn là cách đúng).
#
#  2. SSH tới floating IP của OpenStack timeout dù security group đã mở. Nguyên nhân: br_netfilter bật
#     (Neutron hybrid-iptables cần) nên rule `MASQUERADE -s 10.10.10.0/24 ! -d 10.10.10.0/24` trong
#     setup-brs.sh cũng NAT cả gói đi QUA bridge qbr/tap (host → floating IP → VM): nguồn bị đổi thành IP
#     eth0 sau DNAT, VM trả lời sai địa chỉ. Xử lý: RETURN sớm cho gói `--physdev-is-bridged`.
#
#  3. ProxyJump (bastion AWS, os-gateway) mở ssh con KHÔNG kế thừa `-i` của Ansible → "Connection closed by
#     UNKNOWN port 65535" ở mọi node phía sau jump host. Xử lý: khai báo IdentityFile trong ~/.ssh/config.
set -euo pipefail
log()  { echo "[deployer-preflight] $*"; }
warn() { echo "[deployer-preflight][WARN] $*"; }

SWAP_MIN_GIB=8          # đã có ≥ ngần này swap thì thôi
SWAP_NEW_GIB=16         # kích thước swapfile tạo mới
SWAPFILE=/swapfile
SETUP_BRS=/usr/local/bin/setup-brs.sh

# ── 1. Swap ──────────────────────────────────────────────────────────────────────────────────────
ram_gib=$(awk '/MemTotal/ {print int($2/1048576)}' /proc/meminfo)
swap_gib=$(awk '/SwapTotal/ {print int($2/1048576)}' /proc/meminfo)
if (( ram_gib >= 28 )); then
  log "RAM ${ram_gib} GiB — đủ, không cần swap"
elif (( swap_gib >= SWAP_MIN_GIB )); then
  log "RAM ${ram_gib} GiB + swap ${swap_gib} GiB — đủ"
else
  free_gib=$(df -BG --output=avail / | tail -1 | tr -dc '0-9')
  if (( free_gib < SWAP_NEW_GIB + 20 )); then
    warn "RAM ${ram_gib} GiB, swap ${swap_gib} GiB nhưng ổ đĩa chỉ còn ${free_gib} GiB — không tạo swap ${SWAP_NEW_GIB} GiB được; deploy có nguy cơ OOM"
  else
    log "RAM ${ram_gib} GiB, swap ${swap_gib} GiB — thiếu, tạo ${SWAPFILE} ${SWAP_NEW_GIB} GiB"
    if [[ ! -f "$SWAPFILE" ]]; then
      sudo fallocate -l "${SWAP_NEW_GIB}G" "$SWAPFILE"
      sudo chmod 600 "$SWAPFILE"
      sudo mkswap "$SWAPFILE" >/dev/null
    fi
    swapon --show=NAME --noheadings | grep -qx "$SWAPFILE" || sudo swapon "$SWAPFILE"
    grep -q "^$SWAPFILE " /etc/fstab || echo "$SWAPFILE none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
    log "swap hiện tại: $(awk '/SwapTotal/ {print int($2/1048576)}' /proc/meminfo) GiB"
  fi
fi

# ── 2. NAT: không masquerade gói đi qua bridge ───────────────────────────────────────────────────
RULE=(POSTROUTING -m physdev --physdev-is-bridged -j RETURN)
if ip link show br-exnat &>/dev/null && sudo iptables -t nat -S POSTROUTING 2>/dev/null | grep -q 'MASQUERADE'; then
  if sudo iptables -t nat -C "${RULE[@]}" 2>/dev/null; then
    log "rule NAT physdev đã có"
  else
    sudo iptables -t nat -I POSTROUTING 1 -m physdev --physdev-is-bridged -j RETURN
    log "đã thêm rule NAT: RETURN cho gói --physdev-is-bridged (trước MASQUERADE)"
  fi
  # Giữ qua reboot: setup-brs.service dựng lại NAT từ file này.
  if [[ -f "$SETUP_BRS" ]] && ! grep -q 'physdev-is-bridged' "$SETUP_BRS"; then
    sudo cp "$SETUP_BRS" "$SETUP_BRS.bak-$(date +%Y%m%d)"
    sudo python3 - "$SETUP_BRS" <<'PYEOF'
import sys
p = sys.argv[1]; s = open(p).read()
add = '''# Gói đi qua bridge (qbr/tap của Neutron, br_netfilter bật) KHÔNG được MASQUERADE — nếu không,
# SSH host -> floating IP bị SNAT sau DNAT và VM trả lời sai địa chỉ.
iptables -t nat -C POSTROUTING -m physdev --physdev-is-bridged -j RETURN 2>/dev/null \\
  || iptables -t nat -I POSTROUTING 1 -m physdev --physdev-is-bridged -j RETURN
'''
marker = 'echo "[setup-brs] done"'
if marker in s:
    open(p, 'w').write(s.replace(marker, add + marker))
PYEOF
    sudo systemctl daemon-reload
    log "đã ghi rule vào $SETUP_BRS (bản gốc: $SETUP_BRS.bak-*)"
  fi
else
  log "không có br-exnat/MASQUERADE trên máy này — bỏ qua bước NAT"
fi

# ── 3. ~/.ssh/config cho ProxyJump ───────────────────────────────────────────────────────────────
SSH_CFG="$HOME/.ssh/config"
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
if grep -qs 'IdentityFile ~/.ssh/ztlab-key' "$SSH_CFG"; then
  log "~/.ssh/config đã khai báo IdentityFile cho lab"
else
  # Chèn ở ĐẦU file, giữ nguyên cấu hình sẵn có phía sau (IdentityFile là danh sách cộng dồn, không ghi đè).
  tmp=$(mktemp)
  cat > "$tmp" <<'EOF'
# ztlab-lab-identityfile — ProxyJump mở ssh con không kế thừa -i của Ansible, nên khai báo key ở đây
Host *
    IdentityFile ~/.ssh/ztlab-key
    IdentityFile ~/.ssh/zta-siem-soar-key

EOF
  [[ -f "$SSH_CFG" ]] && cat "$SSH_CFG" >> "$tmp"
  mv "$tmp" "$SSH_CFG" && chmod 600 "$SSH_CFG"
  log "đã thêm IdentityFile ztlab-key + zta-siem-soar-key vào ~/.ssh/config"
fi
