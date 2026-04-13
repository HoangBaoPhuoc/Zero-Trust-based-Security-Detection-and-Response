terraform {
  required_version = ">= 1.0"
  required_providers {
    openstack = {
      source  = "terraform-provider-openstack/openstack"
      version = "~> 1.54"
    }
  }
}

provider "openstack" {
}

data "openstack_networking_network_v2" "external" {
  name = var.external_network_name
}

# Edge Router - entry point from external network
resource "openstack_networking_router_v2" "edge_router" {
  name                = "zta-edge-router"
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.external.id
}

# DMZ Network - directly attached to edge router
resource "openstack_networking_network_v2" "dmz" {
  name           = "zta-dmz-network"
  admin_state_up = true
}

resource "openstack_networking_subnet_v2" "dmz_subnet" {
  name            = "zta-dmz-subnet"
  network_id      = openstack_networking_network_v2.dmz.id
  cidr            = "192.168.100.0/24"
  ip_version      = 4
  gateway_ip      = "192.168.100.1"
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]
}

resource "openstack_networking_router_interface_v2" "edge_router_dmz" {
  router_id = openstack_networking_router_v2.edge_router.id
  subnet_id = openstack_networking_subnet_v2.dmz_subnet.id
}

# Private Network - backend services, accessed through DMZ gateway
resource "openstack_networking_network_v2" "private" {
  name           = "zta-private-network"
  admin_state_up = true

  # Keep DMZ creation first so Horizon topology renders the security edge zone before backend zones.
  depends_on = [openstack_networking_network_v2.dmz]
}

resource "openstack_networking_subnet_v2" "private_subnet" {
  name            = "zta-private-subnet"
  network_id      = openstack_networking_network_v2.private.id
  cidr            = "192.168.101.0/24"
  ip_version      = 4
  gateway_ip      = "192.168.101.1"
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]

  allocation_pool {
    start = "192.168.101.20"
    end   = "192.168.101.253"
  }
}

# Identity Network - Keycloak and authentication services
resource "openstack_networking_network_v2" "identity" {
  name           = "zta-identity-network"
  admin_state_up = true

  # Keep DMZ creation first so Horizon topology renders the security edge zone before backend zones.
  depends_on = [openstack_networking_network_v2.dmz]
}

resource "openstack_networking_subnet_v2" "identity_subnet" {
  name            = "zta-identity-subnet"
  network_id      = openstack_networking_network_v2.identity.id
  cidr            = "192.168.102.0/24"
  ip_version      = 4
  gateway_ip      = "192.168.102.1"
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]

  allocation_pool {
    start = "192.168.102.20"
    end   = "192.168.102.253"
  }
}

# Gateway transit ports: disable port security to allow L3 forwarding traffic.
resource "openstack_networking_port_v2" "os_gateway_private_port" {
  name                  = "os-gateway-private-port"
  network_id            = openstack_networking_network_v2.private.id
  admin_state_up        = true
  port_security_enabled = false

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.private_subnet.id
    ip_address = "192.168.101.1"
  }
}

resource "openstack_networking_port_v2" "os_gateway_identity_port" {
  name                  = "os-gateway-identity-port"
  network_id            = openstack_networking_network_v2.identity.id
  admin_state_up        = true
  port_security_enabled = false

  fixed_ip {
    subnet_id  = openstack_networking_subnet_v2.identity_subnet.id
    ip_address = "192.168.102.1"
  }
}

resource "openstack_compute_instance_v2" "os_gateway" {
  name            = "os-gateway"
  image_name      = var.image_name
  flavor_name     = var.flavor_gateway
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_dmz.name]

  user_data = base64gzip(templatefile("${path.module}/cloud-init-gateway.yaml", {
    public_key = file("~/.ssh/zta-siem-soar-key.pub")
  }))

  network {
    name           = openstack_networking_network_v2.dmz.name
    uuid           = openstack_networking_network_v2.dmz.id
    fixed_ip_v4    = "192.168.100.10"
    access_network = true
  }

  network {
    port = openstack_networking_port_v2.os_gateway_private_port.id
  }

  network {
    port = openstack_networking_port_v2.os_gateway_identity_port.id
  }

  depends_on = [
    openstack_networking_router_interface_v2.edge_router_dmz,
    openstack_networking_subnet_v2.dmz_subnet,
    openstack_networking_subnet_v2.private_subnet,
    openstack_networking_subnet_v2.identity_subnet,
  ]
}

resource "openstack_networking_floatingip_v2" "os_gateway_fip" {
  pool = data.openstack_networking_network_v2.external.name
}

# Get DMZ network port for os-gateway to associate floating IP
data "openstack_networking_port_v2" "os_gateway_dmz_port" {
  network_id = openstack_networking_network_v2.dmz.id
  device_id  = openstack_compute_instance_v2.os_gateway.id

  depends_on = [openstack_compute_instance_v2.os_gateway]
}

resource "openstack_networking_floatingip_associate_v2" "os_gateway_fip_assoc" {
  floating_ip = openstack_networking_floatingip_v2.os_gateway_fip.address
  port_id     = data.openstack_networking_port_v2.os_gateway_dmz_port.id
}

resource "openstack_compute_instance_v2" "os_k3s_master" {
  name            = "os-k3s-master"
  image_name      = var.image_name
  flavor_name     = var.flavor_k3s_master
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_private.name]

  user_data = base64gzip(templatefile("${path.module}/cloud-init.yaml", {
    public_key = file("~/.ssh/zta-siem-soar-key.pub")
  }))

  network {
    uuid        = openstack_networking_network_v2.private.id
    fixed_ip_v4 = "192.168.101.11"
  }

  depends_on = [
    openstack_compute_instance_v2.os_gateway,
    openstack_networking_subnet_v2.private_subnet
  ]
}

resource "openstack_compute_instance_v2" "os_k3s_worker_1" {
  name            = "os-k3s-worker-1"
  image_name      = var.image_name
  flavor_name     = var.flavor_k3s_worker
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_private.name]

  user_data = base64gzip(templatefile("${path.module}/cloud-init.yaml", {
    public_key = file("~/.ssh/zta-siem-soar-key.pub")
  }))

  network {
    uuid        = openstack_networking_network_v2.private.id
    fixed_ip_v4 = "192.168.101.12"
  }

  depends_on = [
    openstack_compute_instance_v2.os_gateway,
    openstack_networking_subnet_v2.private_subnet
  ]
}

resource "openstack_compute_instance_v2" "os_k3s_worker_2" {
  name            = "os-k3s-worker-2"
  image_name      = var.image_name
  flavor_name     = var.flavor_k3s_worker
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_private.name]

  user_data = base64gzip(templatefile("${path.module}/cloud-init.yaml", {
    public_key = file("~/.ssh/zta-siem-soar-key.pub")
  }))

  network {
    uuid        = openstack_networking_network_v2.private.id
    fixed_ip_v4 = "192.168.101.13"
  }

  depends_on = [
    openstack_compute_instance_v2.os_gateway,
    openstack_networking_subnet_v2.private_subnet
  ]
}

resource "openstack_compute_instance_v2" "os_identity" {
  name            = "os-identity"
  image_name      = var.image_name
  flavor_name     = var.flavor_identity
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_identity.name]

  user_data = base64gzip(templatefile("${path.module}/cloud-init.yaml", {
    public_key = file("~/.ssh/zta-siem-soar-key.pub")
  }))

  network {
    name        = openstack_networking_network_v2.identity.name
    uuid        = openstack_networking_network_v2.identity.id
    fixed_ip_v4 = "192.168.102.10"
  }

  depends_on = [
    openstack_compute_instance_v2.os_gateway,
    openstack_networking_subnet_v2.identity_subnet
  ]

  # Prevent provider diff churn from forcing instance recreation on unchanged NIC wiring.
  lifecycle {
    ignore_changes = [network]
  }
}
