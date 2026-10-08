#!/usr/bin/env bash
# Tiền kiểm control-plane OpenStack AIO (Kolla, chạy ngay trên máy deployer) trước khi Terraform
# tạo VM. Gọi từ scripts/deploy-all.sh bước 6.
#
# Sự cố thật 2026-10-04 (mục 3.6 đóng sổ): máy khởi động với đồng hồ hệ thống lệch +7 h (RTC bị ghi
# theo giờ địa phương — dual-boot — nhưng Linux đọc RTC là UTC). Toàn bộ container Kolla khởi động
# trong 5 phút đó; rồi chrony bước lùi 25 199 s. Từ đó nova-scheduler không trả lời RPC: destroy vẫn
# chạy (không cần scheduler), nhưng mọi VM mới kẹt BUILD rồi ERROR `MessagingTimeout`, Terraform chờ
# 30 phút mới báo lỗi. Dấu hiệu tất định: `docker inspect .State.StartedAt` của container nằm Ở TƯƠNG LAI.
# Xử lý: khởi động lại các container đó theo thứ tự phụ thuộc, rồi xác nhận nova-scheduler trả lời
# (`openstack compute service list` + kiểm tra RPC thật bằng `server create --dry`-tương đương: hỏi
# placement allocation candidates).
set -euo pipefail
log()  { echo "[aio-preflight] $*"; }

# Giai đoạn B §1.5 — SỬA TẬN GỐC đồng hồ, không chỉ phản ứng triệu chứng.
# Gốc sự cố 2026-10-04: RTC ghi theo GIỜ ĐỊA PHƯƠNG (dual-boot Windows) nhưng
# Linux đọc RTC là UTC → lệch +7h lúc boot → chrony bước lùi 25 199 s → Kolla
# kẹt. Logic khởi động lại container bên dưới chỉ CHỮA triệu chứng mỗi lần.
# `set-local-rtc 0` buộc Linux coi RTC là UTC vĩnh viễn → không còn lệch lúc
# boot. Idempotent (chạy lại vô hại); cần quyền (sudo), không fatal nếu thiếu.
if command -v timedatectl >/dev/null 2>&1; then
  if [[ "$(timedatectl show -p LocalRTC --value 2>/dev/null || echo no)" == "yes" ]]; then
    log "RTC đang ở giờ địa phương — đặt lại UTC (set-local-rtc 0) để chặn gốc lệch giờ lúc boot"
    sudo timedatectl set-local-rtc 0 --adjust-system-clock 2>/dev/null \
      || log "CẢNH BÁO: không set được local-rtc (thiếu quyền?) — chạy tay: sudo timedatectl set-local-rtc 0 --adjust-system-clock"
  else
    log "RTC đã ở UTC (LocalRTC=no) — ok"
  fi
fi
# CLI: dùng bản trong kolla-venv (7.x, có `server create --no-network`). Bản snap 5.8 không tạo được VM
# không NIC ("nics must be a list or a tuple" — gặp thật ở lần dựng 2026-10-04) và không nhận microversion.
OSC="$HOME/kolla-venv/bin/openstack"; [[ -x "$OSC" ]] || OSC=""
openstack() { if [[ -n "$OSC" ]]; then "$OSC" "$@"; else command openstack "$@"; fi; }
command -v docker >/dev/null || { log "không có docker — bỏ qua (OpenStack không chạy trên máy này)"; exit 0; }
docker ps --format '{{.Names}}' | grep -q '^nova_scheduler$' || { log "không thấy nova_scheduler — bỏ qua"; exit 0; }

now=$(date +%s); future=()
for c in $(docker ps --format '{{.Names}}'); do
  s=$(date -d "$(docker inspect -f '{{.State.StartedAt}}' "$c")" +%s)
  (( s > now + 60 )) && future+=("$c")
done

if (( ${#future[@]} > 0 )); then
  log "${#future[@]} container khởi động TRƯỚC khi đồng hồ hệ thống bị chỉnh lùi (StartedAt ở tương lai) — khởi động lại theo thứ tự phụ thuộc"
  order=(keepalived haproxy proxysql mariadb memcached rabbitmq keystone_fernet keystone_ssh keystone glance_api placement_api
         nova_libvirt nova_ssh nova_conductor nova_scheduler nova_api nova_metadata nova_novncproxy nova_compute
         openvswitch_db openvswitch_vswitchd neutron_server neutron_openvswitch_agent neutron_dhcp_agent
         neutron_l3_agent neutron_metadata_agent)
  done_set=" "
  for c in "${order[@]}" "${future[@]}"; do
    [[ " ${future[*]} " == *" $c "* && "$done_set" != *" $c "* ]] || continue
    docker restart "$c" >/dev/null && done_set+="$c " && log "  restart $c"
    case "$c" in mariadb|rabbitmq) sleep 20 ;; esac
  done
  sleep 30
fi

# Xác nhận THẬT: "compute service up" KHÔNG đủ (lúc hỏng cả 3 dịch vụ vẫn báo up vì heartbeat vẫn chạy).
# Tạo 1 VM thử không NIC (không phụ thuộc network do Terraform tạo), chờ ACTIVE, rồi xoá.
# Keystone (qua VIP haproxy/keepalived) phải trả lời trước — nếu không thì mọi lệnh openstack lỗi và
# KHÔNG được hiểu nhầm thành "chưa có flavor/image".
for i in $(seq 1 40); do openstack token issue -f value -c id >/dev/null 2>&1 && break; sleep 15; done
openstack token issue -f value -c id >/dev/null 2>&1 || { log "Keystone không trả lời sau 10 phút"; exit 1; }
probe="aio-preflight-$(date +%s)"
flavor="$(openstack flavor list -f value -c Name | grep -m1 -E '^(nano-plus|m1.tiny|m1.small|m1.medium)$' || true)"
image="$(openstack image list -f value -c Name | grep -m1 -E '^ubuntu-22.04$' || true)"
if [[ -z "$flavor" || -z "$image" ]]; then log "chưa có flavor/image (bước 6–7 sẽ tạo) — bỏ qua phép thử VM"; exit 0; fi
[[ -n "$OSC" ]] || { log "CẢNH BÁO: không có ~/kolla-venv/bin/openstack — bỏ qua phép thử VM"; exit 0; }
openstack server create --flavor "$flavor" --image "$image" --no-network "$probe" -f value -c id >/dev/null
st=""
for i in $(seq 1 36); do
  st="$(openstack server show "$probe" -f value -c status 2>/dev/null || echo ?)"
  [[ "$st" == ACTIVE || "$st" == ERROR ]] && break
  sleep 5
done
fault="$(openstack server show "$probe" -f value -c fault 2>/dev/null | head -c 200 || true)"
openstack server delete --wait "$probe" >/dev/null 2>&1 || true
if [[ "$st" == ACTIVE ]]; then log "nova lập lịch + tạo VM thử OK"; exit 0; fi
log "VM thử không ACTIVE (status=$st ${fault}) — control-plane OpenStack hỏng; kiểm docker logs nova_scheduler / rabbitmq"
exit 1
