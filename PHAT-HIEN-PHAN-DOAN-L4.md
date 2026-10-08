# PHÁT HIỆN — Phân đoạn theo địa chỉ (L4) không biểu diễn nổi ràng buộc mà phân đoạn theo danh tính (L7) biểu diễn được

> Mục riêng cho luận văn (chương Kết quả / Bàn luận), nâng cấp từ hạn chế H3. Đây **không** phải lỗi được sửa trong phạm vi
> khoá luận mà là **bằng chứng thực nghiệm trực tiếp** cho luận điểm trung tâm: phân đoạn theo danh tính workload (SPIFFE +
> PDP) biểu diễn và thực thi được ràng buộc "ai được gọi ai" giữa các pod cùng namespace, trong khi phân đoạn theo IP/cổng
> (Kubernetes NetworkPolicy) — trên chính hạ tầng này — không thực thi được ràng buộc đó.
> Dữ liệu thô: `results/closeout/netpol/` (đo lại 2026-10-04 trên cụm dựng từ trống), `results/round3/` (đo 2026-09-25/26).

## 1. Câu hỏi

Hệ thống có hai lớp phân đoạn đông–tây cho namespace `crapi`, cùng sinh từ một nguồn sự thật (`policy/service-graph-crapi.yaml`):

- **L4** — NetworkPolicy (bộ điều khiển kube-router nhúng trong k3s): `*-allow-list.yaml` (baseline `podSelector: {}`,
  default-deny Ingress+Egress, egress cho phép DNS/istiod/Loki/cross-cloud và các cổng đích nội ns) + `*-pod-segmentation.yaml`
  (mỗi đích một policy, ingress chỉ từ các nguồn có edge trong service-graph).
- **L7** — mТLS STRICT (danh tính SPIFFE do SPIRE cấp) + OPA ext_authz đánh giá `service_acl[source_principal][destination_principal][method]`.

Câu hỏi: với cùng một ràng buộc ("`crapi-web` không được gọi `crapi-workshop`"), lớp nào thực thi được?

## 2. Phương pháp

1. **Ma trận đầy đủ** `tests/netpol_matrix.sh` — 22 ô: mỗi ô là một cặp (nguồn, đích:cổng) với kỳ vọng `reach`/`block` suy từ
   service-graph; đo bằng kết nối TCP thật (curl exit 0 = tới được, 7 = reject, 28 = drop), có ô đối chứng chứng minh cổng đích tự
   nó mở.
2. **Thí nghiệm cô lập** `tests/netpol_podselector_probe.sh` — namespace tạm `netpol-probe`, không sidecar, không policy nào khác
   của hệ thống; 3 pod (`srv` nginx, `a` được phép, `c` không được phép), đo cùng node và khác node:
   - biến thể `single`: chỉ một policy "ingress vào `srv` chỉ từ `a`";
   - biến thể `egress-shadow`: thêm đúng hình dạng baseline của hệ thống — policy `podSelector: {}` Ingress+Egress, có rule egress
     "cùng ns, cổng 80", **không** có rule ingress.
3. Đối chiếu với L7: cùng cặp nguồn–đích, request HTTP thật qua sidecar → OPA decision log (`opa_result=false`) và mã 403.

## 3. Kết quả

| Phép đo | Kết quả |
|---|---|
| Ma trận 22 ô (2026-09-26, `results/round3/netpol_matrix.txt`) | 14 MATCH / 8 MISMATCH — cả 8 MISMATCH là ô "kỳ vọng chặn" có nguồn **trong** ns `crapi` (hoặc `monitoring → redis`) mà vẫn thông |
| Ma trận 22 ô (2026-10-04, cụm dựng từ trống, `results/closeout/netpol/netpol_matrix.txt`) | **14 MATCH / 8 MISMATCH — đúng 8 ô như lần đo 2026-09-26** (crapi-web → bff/workshop/redis/mongodb, community → bff/redis, bff → mongodb, monitoring → redis) |
| Nguồn ngoài ns (`default → bff/opa`) | bị chặn đúng (exit 7) |
| Egress cross-cloud (community → k3s API/SSH OpenStack) | bị chặn đúng, có ô đối chứng |
| Probe `single` (2 cụm, cùng/khác node) | 8/8 MATCH — policy `podSelector` đơn lẻ thực thi đúng (2026-09-25 và lặp lại 2026-10-04 trên cụm dựng từ trống, cả AWS lẫn OpenStack: `results/closeout/netpol/podselector_probe_{aws,openstack}.txt`) |
| Probe `egress-shadow` (2 cụm, cùng/khác node) | `c → srv:80` **thông** dù không policy nào cho phép — 2/2 MISMATCH mỗi cụm, tái hiện y hệt 2026-10-04 trên hạ tầng mới hoàn toàn (VM, node, k3s, tài khoản AWS mới) |
| L7 cùng cặp (vd `crapi-community → crapi-workshop`) | 403, decision `opa_result=false` gắn đúng request thử |

**Diễn giải:** rule egress "cùng ns :cổng" của baseline được kube-router áp như một quyền *cho phép* ở phía ingress của pod đích,
làm thủng default-deny ingress đúng cho các cổng nằm trong danh sách egress (80, 6379, 8000, 8080, 8087, 8181, 9191, 27017). Theo
đặc tả NetworkPolicy, ingress và egress được đánh giá độc lập và một kết nối phải được **cả hai** phía cho phép; hành vi đo được
lệch khỏi đặc tả. Hai chẩn đoán trước đó ("kube-router không enforce đáng tin cậy", "node thiếu `ipset`") đã bị bác bỏ bằng thực
nghiệm (`AUDIT-THUC-THI.md` §3).

## 4. Vì sao đây là bằng chứng cho luận điểm, không chỉ là một lỗi

- **Biểu diễn:** để L4 biểu diễn đúng ràng buộc "chỉ `bff` được gọi `crapi-workshop:8000`" thì *mỗi pod nguồn* phải có policy egress
  riêng liệt kê đích của nó, và mọi luồng ngoài đồ thị (posture-agent, seed job, sidecar → istiod/Loki) phải được khai thêm. Ràng
  buộc nằm trên cặp (IP, cổng) — thứ thay đổi theo vòng đời pod và bị NAT ở biên cross-cloud (ghi chú H5: `ipBlock` CIDR chính xác
  không khớp với ingress đã NAT). L7 biểu diễn cùng ràng buộc bằng **một dòng** trong `service_acl` gắn với danh tính mật mã của
  workload, không phụ thuộc IP, đúng cả nội cụm lẫn xuyên cloud.
- **Thực thi:** trên hạ tầng thật, lớp L4 đã sinh đúng, apply đúng, `kubectl get netpol` thấy đủ — nhưng không chặn. Chỉ một phép
  thử sống hai vế (H7) mới phát hiện được. L7 trên cùng cặp chặn được và để lại bằng chứng đánh giá (decision log) cho từng request.
- **Hệ quả thiết kế:** "defense in depth" chỉ đúng khi từng lớp được chứng minh thực thi. Trong hệ thống này, câu đúng là:
  *"L4 chặn nguồn ngoài namespace và egress cross-cloud; phân đoạn nội namespace do L7 (mTLS + PDP) đảm nhiệm."* `redis --requirepass`
  và `mongod --auth` là lớp bù cho đích không có sidecar.

## 5. Giới hạn và hướng làm tiếp

- Chưa đối chiếu với bộ điều khiển NetworkPolicy khác (Calico/Cilium) trên cùng ma trận — đó là phép thử phân biệt "lỗi của kube-router"
  với "giới hạn chung của L4". Giữ nguyên `tests/netpol_matrix.sh` + `tests/netpol_podselector_probe.sh` làm cổng nghiệm thu.
- Sửa trong phạm vi hiện tại (policy egress theo từng nguồn) không làm vì rủi ro gãy deploy ở giai đoạn cuối; L7 đã phân đoạn được.
- (Tuỳ chọn) báo lỗi lên dự án kube-router kèm `tests/netpol_podselector_probe.sh` biến thể `egress-shadow` làm bản tái hiện tối thiểu.
