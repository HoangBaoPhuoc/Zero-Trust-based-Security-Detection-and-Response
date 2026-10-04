"""Mục 2.3 — ước lượng dung lượng log 150 giờ từ samples.csv (lấy mẫu 5 phút).
In: tốc độ byte THÔ vào Loki (theo cụm, từ bytes_over_time 5m), tốc độ tăng trên
đĩa (du thư mục PVC Loki), và ngoại suy 150 h có biên an toàn 100%."""
import csv, statistics, sys
rows = list(csv.DictReader(open(sys.argv[1] if len(sys.argv) > 1 else "results/closeout/log-volume/samples.csv")))
f = lambda r, k: float(r[k]) if r[k] not in ("", None) else 0.0
t0, t1 = f(rows[0], "ts"), f(rows[-1], "ts")
hours = (t1 - t0) / 3600
aws5 = [f(r, "bytes5m_aws") for r in rows]; os5 = [f(r, "bytes5m_openstack") for r in rows]
recv = (f(rows[-1], "bytes_received_total") - f(rows[0], "bytes_received_total")) / hours
disk = (f(rows[-1], "du_loki") - f(rows[0], "du_loki")) / hours
prom = (f(rows[-1], "du_prom") - f(rows[0], "du_prom")) / hours
MB = 1e6
print(f"cửa sổ đo: {hours:.2f} h, {len(rows)} mẫu")
print(f"byte thô/giờ (bytes_over_time, trung bình 5-phút×12): AWS {statistics.mean(aws5)*12/MB:.1f} MB/h, "
      f"OpenStack {statistics.mean(os5)*12/MB:.1f} MB/h  (min–max 5 phút AWS {min(aws5)/MB:.2f}–{max(aws5)/MB:.2f} MB, "
      f"OS {min(os5)/MB:.2f}–{max(os5)/MB:.2f} MB)")
print(f"distributor bytes_received: {recv/MB:.1f} MB/h (cả 2 cụm)")
print(f"tăng trên đĩa Loki (du): {disk/MB:.1f} MB/h ; Prometheus: {prom/MB:.1f} MB/h")
for name, rate in (("raw", recv), ("đĩa Loki", disk), ("đĩa Prometheus", prom)):
    print(f"150 h × {name}: {rate*150/1e9:.2f} GB → ×2 biên an toàn: {rate*300/1e9:.2f} GB")
print(f"root_avail node Loki: đầu {f(rows[0],'root_avail')/1e9:.2f} GB → cuối {f(rows[-1],'root_avail')/1e9:.2f} GB")
