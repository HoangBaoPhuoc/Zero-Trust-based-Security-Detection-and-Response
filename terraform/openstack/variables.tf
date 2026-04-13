variable "os_auth_url" {
  description = "OpenStack auth URL (from OS_AUTH_URL environment)"
  type        = string
  default     = ""
}

variable "os_username" {
  description = "OpenStack username (from OS_USERNAME environment)"
  type        = string
  default     = ""
}

variable "os_password" {
  description = "OpenStack password (from OS_PASSWORD environment)"
  type        = string
  sensitive   = true
  default     = ""
}

variable "os_project_name" {
  description = "OpenStack project/tenant name (from OS_PROJECT_NAME environment)"
  type        = string
  default     = ""
}

variable "os_region" {
  description = "OpenStack region (from OS_REGION_NAME environment)"
  type        = string
  default     = ""
}

variable "os_project_domain_name" {
  description = "OpenStack project domain name (from OS_PROJECT_DOMAIN_NAME environment)"
  type        = string
  default     = "Default"
}

variable "os_user_domain_name" {
  description = "OpenStack user domain name (from OS_USER_DOMAIN_NAME environment)"
  type        = string
  default     = "Default"
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

variable "management_cidr" {
  description = "Trusted management CIDR allowed to SSH into os-gateway floating IP"
  type        = string
  default     = "172.10.10.1/32"
}

variable "aio_provider_cidr" {
  description = "AIO/provider bridge CIDR allowed to bootstrap SSH into OpenStack private/identity nodes"
  type        = string
  default     = "172.10.10.1/32"
}
