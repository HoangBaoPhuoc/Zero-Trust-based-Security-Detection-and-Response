terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  primary_az          = var.aws_primary_az != null ? var.aws_primary_az : data.aws_availability_zones.available.names[0]
  effective_key_pair  = var.create_key_pair ? aws_key_pair.ztlab[0].key_name : var.key_pair_name
  resolved_public_key = pathexpand(var.public_key_path)
}

data "aws_ami" "ubuntu22" {
  most_recent = true
  owners      = [var.ami_owner]

  filter {
    name   = "name"
    values = [var.ami_name_filter]
  }
}

resource "aws_vpc" "ztlab" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "ztlab-vpc", Project = "ztlab" }
}

resource "aws_internet_gateway" "ztlab" {
  vpc_id = aws_vpc.ztlab.id
  tags   = { Name = "ztlab-igw" }
}

resource "aws_subnet" "dmz" {
  vpc_id                  = aws_vpc.ztlab.id
  cidr_block              = var.dmz_subnet_cidr
  availability_zone       = local.primary_az
  map_public_ip_on_launch = true
  tags                    = { Name = "ztlab-dmz" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.ztlab.id
  cidr_block              = var.private_subnet_cidr
  availability_zone       = local.primary_az
  map_public_ip_on_launch = false
  tags                    = { Name = "ztlab-private" }
}

resource "aws_subnet" "restricted_a" {
  vpc_id                  = aws_vpc.ztlab.id
  cidr_block              = var.restricted_a_subnet_cidr
  availability_zone       = local.primary_az
  map_public_ip_on_launch = false
  tags                    = { Name = "ztlab-restricted-a" }
}

resource "aws_subnet" "restricted_b" {
  vpc_id                  = aws_vpc.ztlab.id
  cidr_block              = var.restricted_b_subnet_cidr
  availability_zone       = local.primary_az
  map_public_ip_on_launch = false
  tags                    = { Name = "ztlab-restricted-b" }
}

resource "aws_subnet" "management" {
  vpc_id                  = aws_vpc.ztlab.id
  cidr_block              = var.management_subnet_cidr
  availability_zone       = local.primary_az
  map_public_ip_on_launch = true
  tags                    = { Name = "ztlab-management" }
}

resource "aws_key_pair" "ztlab" {
  count      = var.create_key_pair ? 1 : 0
  key_name   = var.key_pair_name
  public_key = trimspace(file(local.resolved_public_key))
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ztlab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ztlab.id
  }
  tags = { Name = "ztlab-public-rt" }
}

resource "aws_route_table_association" "dmz" {
  subnet_id      = aws_subnet.dmz.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "management" {
  subnet_id      = aws_subnet.management.id
  route_table_id = aws_route_table.public.id
}

# Private and restricted subnets egress through aws_gateway (NAT instance).
resource "aws_route_table" "private_egress" {
  vpc_id = aws_vpc.ztlab.id

  route {
    cidr_block           = "0.0.0.0/0"
    network_interface_id = aws_instance.aws_gateway.primary_network_interface_id
  }

  tags = { Name = "ztlab-private-egress-rt" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private_egress.id
}

resource "aws_route_table_association" "restricted_a" {
  subnet_id      = aws_subnet.restricted_a.id
  route_table_id = aws_route_table.private_egress.id
}

resource "aws_route_table_association" "restricted_b" {
  subnet_id      = aws_subnet.restricted_b.id
  route_table_id = aws_route_table.private_egress.id
}

resource "aws_eip" "wg_gateway" {
  domain = "vpc"
  tags   = { Name = "ztlab-wg-gateway-eip" }
}

resource "aws_instance" "aws_gateway" {
  ami                         = data.aws_ami.ubuntu22.id
  instance_type               = var.instance_type_gateway
  subnet_id                   = aws_subnet.dmz.id
  private_ip                  = var.gateway_private_ip
  key_name                    = local.effective_key_pair
  associate_public_ip_address = true
  source_dest_check           = false
  vpc_security_group_ids      = [aws_security_group.sg_dmz.id]
  tags                        = { Name = "aws-gateway", Role = "wg-server" }
}

resource "aws_eip_association" "wg_eip_assoc" {
  instance_id   = aws_instance.aws_gateway.id
  allocation_id = aws_eip.wg_gateway.id
}

resource "aws_instance" "aws_k3s_master" {
  ami                    = data.aws_ami.ubuntu22.id
  instance_type          = var.instance_type_k3s_master
  subnet_id              = aws_subnet.private.id
  private_ip             = "10.10.1.10"
  key_name               = local.effective_key_pair
  vpc_security_group_ids = [aws_security_group.sg_private.id]
  root_block_device { volume_size = 30 }
  tags = { Name = "aws-k3s-master", Role = "k3s-master" }
}

resource "aws_instance" "aws_k3s_worker_1" {
  ami                    = data.aws_ami.ubuntu22.id
  instance_type          = var.instance_type_k3s_worker
  subnet_id              = aws_subnet.private.id
  private_ip             = "10.10.1.11"
  key_name               = local.effective_key_pair
  vpc_security_group_ids = [aws_security_group.sg_private.id]
  root_block_device { volume_size = 30 }
  tags = { Name = "aws-k3s-worker-1", Role = "k3s-worker" }
}

resource "aws_instance" "aws_k3s_worker_2" {
  ami                    = data.aws_ami.ubuntu22.id
  instance_type          = var.instance_type_k3s_worker
  subnet_id              = aws_subnet.private.id
  private_ip             = "10.10.1.12"
  key_name               = local.effective_key_pair
  vpc_security_group_ids = [aws_security_group.sg_private.id]
  root_block_device { volume_size = 30 }
  tags = { Name = "aws-k3s-worker-2", Role = "k3s-worker" }
}

resource "aws_instance" "aws_security" {
  ami                    = data.aws_ami.ubuntu22.id
  instance_type          = var.instance_type_security
  subnet_id              = aws_subnet.private.id
  private_ip             = "10.10.1.20"
  key_name               = local.effective_key_pair
  vpc_security_group_ids = [aws_security_group.sg_private.id]
  root_block_device { volume_size = 30 }
  tags = { Name = "aws-security", Role = "spire-keycloak" }
}

resource "aws_instance" "aws_siem" {
  ami                    = data.aws_ami.ubuntu22.id
  instance_type          = var.instance_type_siem
  subnet_id              = aws_subnet.restricted_a.id
  private_ip             = "10.10.2.10"
  key_name               = local.effective_key_pair
  vpc_security_group_ids = [aws_security_group.sg_restricted.id]
  root_block_device { volume_size = 50 }
  tags = { Name = "aws-siem", Role = "siem" }
}

resource "aws_instance" "aws_bastion" {
  ami                         = data.aws_ami.ubuntu22.id
  instance_type               = var.instance_type_bastion
  subnet_id                   = aws_subnet.management.id
  private_ip                  = "10.10.4.10"
  key_name                    = local.effective_key_pair
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.sg_management.id]
  tags                        = { Name = "aws-bastion", Role = "bastion" }
}
