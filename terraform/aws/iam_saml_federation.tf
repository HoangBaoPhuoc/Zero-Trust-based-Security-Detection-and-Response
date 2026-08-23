# AWS IAM SAML federation — Keycloak làm SAML IdP cho AWS Console SSO.
#
# Phạm vi CÓ CHỦ ĐÍCH hẹp: chỉ phục vụ admin đăng nhập AWS Console qua SSO
# (demo khái niệm federation), KHÔNG phải luồng chính của app tài chính (app
# dùng SPIFFE/SPIRE cho workload identity, OIDC/PKCE cho user — không đụng
# AWS IAM). Xem README.md "Vì sao những lựa chọn thiết kế còn lại" — mục
# "vì sao tự dựng VM thay vì PaaS" giải thích lý do app không phụ thuộc AWS IAM.
#
# saml_metadata_document lấy TRỰC TIẾP từ Keycloak thật đang chạy
# (http://localhost:8180/realms/ztlab/protocol/saml/descriptor) — không phải
# file mẫu/giả lập. Client SAML "aws-console-sso" tạo qua Keycloak Admin API,
# cấu hình gốc nằm trong k8s/keycloak/realm-config.json.

variable "keycloak_saml_metadata_path" {
  description = "Đường dẫn file metadata XML của Keycloak SAML IdP (lấy từ /realms/ztlab/protocol/saml/descriptor). Rỗng = bỏ qua tạo SAML provider."
  type        = string
  default     = ""
}

resource "aws_iam_saml_provider" "keycloak" {
  count                  = var.keycloak_saml_metadata_path != "" ? 1 : 0
  name                   = "ztlab-keycloak"
  saml_metadata_document = file(var.keycloak_saml_metadata_path)
}

# IAM Role demo — admin đăng nhập qua Keycloak SAML được assume role này để
# vào AWS Console. Quyền hạn chế (ReadOnlyAccess) — đây là demo federation,
# không phải role vận hành thật.
resource "aws_iam_role" "ztlab_sso_admin" {
  count = var.keycloak_saml_metadata_path != "" ? 1 : 0
  name  = "ztlab-sso-admin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_saml_provider.keycloak[0].arn }
      Action    = "sts:AssumeRoleWithSAML"
      Condition = {
        StringEquals = {
          "SAML:aud" = "https://signin.aws.amazon.com/saml"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ztlab_sso_admin_readonly" {
  count      = var.keycloak_saml_metadata_path != "" ? 1 : 0
  role       = aws_iam_role.ztlab_sso_admin[0].name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "aws_saml_provider_arn" {
  value       = var.keycloak_saml_metadata_path != "" ? aws_iam_saml_provider.keycloak[0].arn : null
  description = "ARN của SAML provider — dùng để cấu hình Keycloak SAML client redirect/audience nếu cần đối chiếu ngược."
}

output "aws_sso_admin_role_arn" {
  value       = var.keycloak_saml_metadata_path != "" ? aws_iam_role.ztlab_sso_admin[0].arn : null
  description = "IAM Role admin đăng nhập qua Keycloak SAML SSO sẽ assume."
}
