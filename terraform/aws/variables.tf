variable "aws_region" {
  type    = string
  default = "ap-southeast-1"
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
