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
  auth_url    = var.os_auth_url
  tenant_name = var.os_project_name
  user_name   = var.os_username
  password    = var.os_password
  region      = var.os_region
}

data "openstack_networking_network_v2" "external" {
  name = var.external_network_name
}

resource "openstack_networking_network_v2" "dmz" {
  name           = "zta-dmz-network"
  admin_state_up = true
}

resource "openstack_networking_network_v2" "private" {
  name           = "zta-private-network"
  admin_state_up = true
}

resource "openstack_networking_network_v2" "identity" {
  name           = "zta-identity-network"
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

resource "openstack_networking_subnet_v2" "private_subnet" {
  name            = "zta-private-subnet"
  network_id      = openstack_networking_network_v2.private.id
  cidr            = "192.168.101.0/24"
  ip_version      = 4
  gateway_ip      = "192.168.101.254"
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]

  allocation_pool {
    start = "192.168.101.2"
    end   = "192.168.101.253"
  }
}

resource "openstack_networking_subnet_v2" "identity_subnet" {
  name            = "zta-identity-subnet"
  network_id      = openstack_networking_network_v2.identity.id
  cidr            = var.identity_subnet_cidr
  ip_version      = 4
  gateway_ip      = "192.168.102.254"
  dns_nameservers = ["8.8.8.8", "8.8.4.4"]

  allocation_pool {
    start = "192.168.102.2"
    end   = "192.168.102.253"
  }
}

resource "openstack_networking_router_v2" "edge_router" {
  name                = "zta-edge-router"
  admin_state_up      = true
  external_network_id = data.openstack_networking_network_v2.external.id
}

resource "openstack_networking_router_interface_v2" "edge_router_dmz" {
  router_id = openstack_networking_router_v2.edge_router.id
  subnet_id = openstack_networking_subnet_v2.dmz_subnet.id
}

resource "openstack_compute_instance_v2" "os_gateway" {
  name            = "os-gateway"
  image_name      = var.image_name
  flavor_name     = var.flavor_gateway
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_dmz.name]

  network {
    uuid        = openstack_networking_network_v2.dmz.id
    fixed_ip_v4 = "192.168.100.10"
  }

  depends_on = [openstack_networking_subnet_v2.dmz_subnet]
}

resource "openstack_compute_interface_attach_v2" "os_gateway_private_interface" {
  instance_id = openstack_compute_instance_v2.os_gateway.id
  network_id  = openstack_networking_network_v2.private.id
  fixed_ip    = "192.168.101.254"

  depends_on = [openstack_networking_subnet_v2.private_subnet]
}

resource "openstack_compute_interface_attach_v2" "os_gateway_identity_interface" {
  instance_id = openstack_compute_instance_v2.os_gateway.id
  network_id  = openstack_networking_network_v2.identity.id
  fixed_ip    = "192.168.102.254"

  depends_on = [openstack_networking_subnet_v2.identity_subnet]
}

resource "openstack_compute_instance_v2" "os_k3s_master" {
  name            = "os-k3s-master"
  image_name      = var.image_name
  flavor_name     = var.flavor_k3s_master
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_private.name]

  network {
    uuid        = openstack_networking_network_v2.private.id
    fixed_ip_v4 = "192.168.101.10"
  }

  depends_on = [openstack_networking_subnet_v2.private_subnet]
}

resource "openstack_compute_instance_v2" "os_k3s_worker_1" {
  name            = "os-k3s-worker-1"
  image_name      = var.image_name
  flavor_name     = var.flavor_k3s_worker
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_private.name]

  network {
    uuid        = openstack_networking_network_v2.private.id
    fixed_ip_v4 = "192.168.101.11"
  }

  depends_on = [openstack_networking_subnet_v2.private_subnet]
}

resource "openstack_compute_instance_v2" "os_k3s_worker_2" {
  name            = "os-k3s-worker-2"
  image_name      = var.image_name
  flavor_name     = var.flavor_k3s_worker
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_private.name]

  network {
    uuid        = openstack_networking_network_v2.private.id
    fixed_ip_v4 = "192.168.101.12"
  }

  depends_on = [openstack_networking_subnet_v2.private_subnet]
}

resource "openstack_compute_instance_v2" "os_identity" {
  name            = "os-identity"
  image_name      = var.image_name
  flavor_name     = var.flavor_identity
  security_groups = [openstack_networking_secgroup_v2.neutron_sg_os_identity.name]

  network {
    uuid        = openstack_networking_network_v2.identity.id
    fixed_ip_v4 = "192.168.102.20"
  }

  depends_on = [openstack_networking_subnet_v2.identity_subnet]
}
