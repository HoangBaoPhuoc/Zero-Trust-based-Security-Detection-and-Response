# Runbook — Keystone OIDC Federation với Keycloak

**Trạng thái: chưa thực thi.** Cần quyền SSH trực tiếp vào OpenStack controller
(`172.16.99.250` theo `OS_AUTH_URL` trong `.env`) — đã thử `ssh ubuntu@172.16.99.250`
và `ssh root@172.16.99.250`, cả hai đều "Host key verification failed" (không có
key/credential nào được cấp cho phiên làm việc này). Đây là giới hạn quyền truy
cập thật, không phải rủi ro tôi chọn bỏ qua — việc này nằm ngoài phạm vi
Terraform/Ansible của repo (chỉ provision VM, không quản lý chính OpenStack
control plane) nên không tự động hoá được từ đây.

Bạn cần tự SSH vào controller (`ssh <user>@172.16.99.250`, dùng đúng credential
bạn có) và chạy các bước dưới theo thứ tự.

## Trước khi bắt đầu — sao lưu

```bash
# Trên controller — backup keystone.conf trước khi sửa
sudo cp /etc/kolla/keystone-*/keystone.conf /etc/kolla/keystone-*/keystone.conf.bak-$(date +%Y%m%d)
```

## Bước 1 — Lấy OIDC discovery document của Keycloak

Từ máy deployer (không cần chạy trên controller):
```bash
bash scripts/k8s-tunnel.sh up all  # nếu chưa có tunnel
curl -s http://localhost:8180/realms/ztlab/.well-known/openid-configuration | python3 -m json.tool
```
Ghi lại `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri` — cần cho Bước 3.

## Bước 2 — Cài Apache module OIDC trên controller (Kolla-Ansible/OpenStack thường dùng Apache+mod_wsgi cho Keystone)

```bash
# Trên controller
sudo apt update
sudo apt install -y libapache2-mod-auth-openidc
sudo a2enmod auth_openidc
```

> Nếu controller dùng container hoá (Kolla containers) thay vì Apache bare-metal, module này cần cài **trong container keystone**, không phải host — kiểm tra `docker ps | grep keystone` trước khi làm bước này. Nếu đúng là container, cần rebuild image keystone với module đã cài thay vì `apt install` trực tiếp trên host.

## Bước 3 — Cấu hình OIDC trong Apache vhost của Keystone

Thêm vào file vhost Keystone (thường `/etc/apache2/sites-available/keystone.conf` hoặc tương đương trong container):

```apache
OIDCProviderMetadataURL http://<AWS-bastion-hoặc-đường-đến-Keycloak>:8180/realms/ztlab/.well-known/openid-configuration
OIDCClientID keystone-federation
OIDCClientSecret <lấy từ Keycloak admin — xem Bước 4>
OIDCRedirectURI http://172.16.99.250:5000/v3/OS-FEDERATION/identity_providers/keycloak/protocols/openid/websso
OIDCCryptoPassphrase <chuỗi ngẫu nhiên tự sinh, dùng openssl rand -hex 32>
OIDCScope "openid profile"

<Location /v3/OS-FEDERATION/identity_providers/keycloak/protocols/openid/websso>
    AuthType openid-connect
    Require valid-user
</Location>
```

**Lưu ý quan trọng:** `OIDCProviderMetadataURL` phải trỏ tới địa chỉ Keycloak mà **controller** gọi được — không phải `localhost:8180` (đó là tunnel riêng của máy deployer). Cần expose Keycloak qua 1 đường mạng mà OpenStack controller reach được (vd. qua WireGuard nếu controller nằm trong cùng mạng lab, hoặc public IP của AWS bastion + port-forward). Đây là phần cấu hình mạng cụ thể theo topology thật của lab, không đoán trước được từ đây.

## Bước 4 — Tạo client OIDC riêng cho Keystone trong Keycloak

Client `api-gateway`/`web-portal` hiện có KHÔNG dùng cho việc này (dành riêng cho luồng app). Tạo client mới:

```bash
ADMIN_TOKEN=$(curl -s -X POST "http://localhost:8180/realms/master/protocol/openid-connect/token" \
  -d "grant_type=password&client_id=admin-cli&username=admin&password=$KEYCLOAK_ADMIN_PASSWORD" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

curl -s -X POST "http://localhost:8180/admin/realms/ztlab/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{
    "clientId": "keystone-federation",
    "protocol": "openid-connect",
    "publicClient": false,
    "standardFlowEnabled": true,
    "redirectUris": ["http://172.16.99.250:5000/v3/OS-FEDERATION/identity_providers/keycloak/protocols/openid/websso"]
  }'

# Lấy client secret vừa tạo để điền vào OIDCClientSecret ở Bước 3
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:8180/admin/realms/ztlab/clients?clientId=keystone-federation" \
  | python3 -c "import json,sys; print(json.load(sys.stdin)[0].get('id'))"
# rồi:  GET /admin/realms/ztlab/clients/<id>/client-secret
```

## Bước 5 — Đăng ký Identity Provider trong Keystone

```bash
# Trên controller, đã source admin-openrc.sh
openstack identity provider create --remote-id "http://keycloak.ztlab.local:8180/realms/ztlab" keycloak

openstack mapping create --rules mapping-rules.json keycloak-mapping
openstack federation protocol create openid --identity-provider keycloak --mapping keycloak-mapping
```

`mapping-rules.json` mẫu (map claim `email`/`groups` từ Keycloak sang Keystone group `ztlab-admins` đã tạo sẵn):
```json
[
  {
    "local": [{"user": {"name": "{0}"}}, {"group": {"name": "ztlab-admins", "domain": {"name": "Default"}}}],
    "remote": [{"type": "OIDC-email"}]
  }
]
```

## Bước 6 — Khởi động lại Apache/Keystone và kiểm thử

```bash
sudo systemctl restart apache2   # hoặc restart container keystone tương ứng
curl -sI http://172.16.99.250:5000/v3/OS-FEDERATION/identity_providers/keycloak/protocols/openid/auth
# Kỳ vọng: redirect (302) tới Keycloak login, không phải lỗi 404/500
```

Test thật: mở trình duyệt tới URL trên, đăng nhập bằng tài khoản Keycloak
(vd. `demoadmin`), xác nhận redirect thành công về Keystone và cấp được unscoped token liên kết với group `ztlab-admins`.

## Rollback nếu có sự cố

```bash
sudo cp /etc/kolla/keystone-*/keystone.conf.bak-<ngày> /etc/kolla/keystone-*/keystone.conf
sudo systemctl restart apache2
openstack identity provider delete keycloak   # nếu cần gỡ hẳn
```

---

*Runbook này viết dựa trên kiến trúc chuẩn Kolla-Ansible/Keystone + mod_auth_openidc — cần điều chỉnh theo cấu hình thật của lab bạn (vị trí file config, cách container hoá) trước khi chạy từng lệnh.*
