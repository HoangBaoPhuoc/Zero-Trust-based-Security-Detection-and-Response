// Mapped from OpenRC: OS_AUTH_URL
variable "os_auth_url" {
  description = "OpenStack auth URL"
  type        = string
  default     = "http://192.168.1.254:5000/v3"
}

// Mapped from OpenRC: OS_PROJECT_NAME
variable "os_project_name" {
  description = "OpenStack project name"
  type        = string
  default     = "ZTA-SIEM-SOAR"
}

// Mapped from OpenRC: OS_USERNAME
variable "os_username" {
  description = "OpenStack username"
  type        = string
  default     = "adminZTA"
}

// Mapped from OpenRC: OS_PASSWORD
variable "os_password" {
  description = "OpenStack password"
  type        = string
  sensitive   = true
  default     = "ZTA123"
}

// Mapped from OpenRC: OS_REGION_NAME
variable "os_region" {
  description = "OpenStack region"
  type        = string
  default     = "RegionOne"
}

variable "image_name" {
  description = "OpenStack image"
  type        = string
  default     = "ubuntu-22.04"
}

variable "key_pair_name" {
  description = "OpenStack keypair"
  type        = string
  default     = "zta-siem-soar-key"
}

variable "flavor_gateway" {
  description = "Flavor for os-gateway"
  type        = string
  default     = "nano-plus"
}

variable "flavor_k3s_master" {
  description = "Flavor for os-k3s-master"
  type        = string
  default     = "m1.medium"
}

variable "flavor_k3s_worker" {
  description = "Flavor for os-k3s-worker nodes"
  type        = string
  default     = "nano"
}

variable "flavor_identity" {
  description = "Flavor for os-identity"
  type        = string
  default     = "nano"
}

variable "external_network_name" {
  description = "OpenStack external network name for router gateway"
  type        = string
  default     = "public1"
}

variable "identity_subnet_cidr" {
  description = "Dedicated identity subnet CIDR"
  type        = string
  default     = "192.168.102.0/24"
}
