resource "aws_security_group" "sg_dmz" {
  name        = "ztlab-sg-dmz"
  description = "DMZ zone security group"
  vpc_id      = aws_vpc.ztlab.id

  ingress {
    from_port   = 51820
    to_port     = 51820
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "WireGuard"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
    description = "SSH admin"
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
    description = "Forwarded traffic from internal subnets"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sg-dmz" }
}

resource "aws_security_group" "sg_private" {
  name        = "ztlab-sg-private"
  description = "Private zone security group"
  vpc_id      = aws_vpc.ztlab.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.sg_dmz.id]
    description     = "App traffic from DMZ"
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.sg_dmz.id]
    description     = "App traffic from DMZ"
  }

  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = [var.private_subnet_cidr]
    description = "K3s API"
  }

  ingress {
    from_port   = 8081
    to_port     = 8081
    protocol    = "tcp"
    cidr_blocks = [var.private_subnet_cidr, var.management_subnet_cidr]
    description = "SPIRE Server"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.10.4.10/32"]
    description = "SSH from bastion"
  }

  ingress {
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.restricted_a_subnet_cidr]
    description = "Prometheus scrape"
  }

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.private_subnet_cidr, "10.44.0.0/16"]
    description = "Intra-zone and cross-cloud pods"
  }

  # crAPI (KE-HOACH-CRAPI.md): identity/postgres nam o OpenStack -> traffic
  # OpenStack to AWS NodePort (mailhog SMTP 31025, va bat ky hop OS to AWS nao
  # khac). Finance app chi co AWS to OS nen dai nay chua tung duoc mo.
  # Nguon: OS k3s subnet + WireGuard subnet (tuy os_gateway co SNAT hay khong).
  # 2026-09-29: aws_gateway MASQUERADE moi traffic ra ens5 (ke ca traffic tu
  # wg0), nen goi tin OpenStack toi node AWS mang nguon = IP private cua
  # gateway, KHONG phai 192.168.101.0/24 -> rule nay truoc day chua tung khop
  # (do: gateway -> 10.10.1.11:31000 bi SG chan). Them IP gateway de duong
  # Promtail OpenStack -> Loki NodePort 31000 qua WireGuard thong ma khong
  # can relay nao tren may nguoi dung.
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["192.168.101.0/24", "10.200.0.0/24", "${var.gateway_private_ip}/32"]
    description = "crAPI OpenStack to AWS NodePort cross-cloud"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sg-private" }
}

resource "aws_security_group" "sg_restricted" {
  name        = "ztlab-sg-restricted"
  description = "Restricted zone security group for PLG Stack (Loki + Grafana)"
  vpc_id      = aws_vpc.ztlab.id

  ingress {
    from_port   = 3100
    to_port     = 3100
    protocol    = "tcp"
    # Vòng 2026-09-29: bỏ "10.10.4.0/24" viết cứng — trùng với
    # var.management_subnet_cidr, AWS lưu 1 bản nên MỌI `terraform plan` đều báo
    # "1 to change" (drift vĩnh viễn, che mất drift thật).
    cidr_blocks = [var.private_subnet_cidr, var.management_subnet_cidr]
    description = "Loki - log collection from all nodes"
  }

  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    cidr_blocks = ["10.10.4.10/32"]
    description = "Grafana web UI - from bastion only"
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.management_subnet_cidr]
    description = "SSH from management"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sg-restricted" }
}

resource "aws_security_group" "sg_management" {
  name        = "ztlab-sg-management"
  description = "Management zone security group"
  vpc_id      = aws_vpc.ztlab.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_ip]
    description = "SSH admin"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "sg-management" }
}
