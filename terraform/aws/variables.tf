variable "aws_region" {
  type    = string
  default = "ap-southeast-1"
}

variable "aws_profile" {
  description = "Optional AWS shared credentials profile (e.g. default, ztlab)."
  type        = string
  default     = null
}

variable "aws_primary_az" {
  description = "Optional explicit AZ. If null, Terraform uses the first available AZ in the selected region."
  type        = string
  default     = null
}

variable "admin_ip" {
  description = "Admin public CIDR for SSH access (x.x.x.x/32)"
  type        = string
  default     = "0.0.0.0/0"
}

variable "key_pair_name" {
  description = "Existing AWS EC2 key pair name"
  type        = string
  default     = "ztlab-key"
}

variable "gateway_private_ip" {
  description = "Private IP for aws-gateway in DMZ subnet. Avoid AWS reserved addresses (.0-.3 and .255)."
  type        = string
  default     = "10.10.0.10"
}

variable "create_key_pair" {
  description = "Create/import an EC2 key pair from public_key_path."
  type        = bool
  default     = false
}

variable "public_key_path" {
  description = "Path to SSH public key file used when create_key_pair is true."
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "vpc_cidr" {
  type    = string
  default = "10.10.0.0/16"
}

variable "dmz_subnet_cidr" {
  type    = string
  default = "10.10.0.0/24"
}

variable "private_subnet_cidr" {
  type    = string
  default = "10.10.1.0/24"
}

variable "restricted_a_subnet_cidr" {
  type    = string
  default = "10.10.2.0/24"
}

variable "restricted_b_subnet_cidr" {
  type    = string
  default = "10.10.3.0/24"
}

variable "management_subnet_cidr" {
  type    = string
  default = "10.10.4.0/24"
}

variable "ami_owner" {
  type    = string
  default = "099720109477"
}

variable "ami_name_filter" {
  type    = string
  default = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
}

variable "instance_type_gateway" {
  type    = string
  default = "t3.micro"
}

variable "instance_type_k3s_master" {
  type    = string
  default = "t3.small"
}

variable "instance_type_k3s_worker" {
  type    = string
  default = "t3.micro"
}

variable "instance_type_security" {
  type    = string
  default = "t3.micro"
}

variable "instance_type_siem" {
  type    = string
  default = "t3.micro"
}

variable "instance_type_bastion" {
  type    = string
  default = "t3.micro"
}
