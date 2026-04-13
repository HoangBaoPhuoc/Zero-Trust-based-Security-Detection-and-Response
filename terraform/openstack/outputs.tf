output "network_ids" {
  value = {
    dmz      = openstack_networking_network_v2.dmz.id
    private  = openstack_networking_network_v2.private.id
    identity = openstack_networking_network_v2.identity.id
  }
}

output "subnet_ids" {
  value = {
    dmz      = openstack_networking_subnet_v2.dmz_subnet.id
    private  = openstack_networking_subnet_v2.private_subnet.id
    identity = openstack_networking_subnet_v2.identity_subnet.id
  }
}

output "router_ids" {
  value = {
    edge = openstack_networking_router_v2.edge_router.id
  }
}

output "security_group_ids" {
  value = {
    dmz      = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
    private  = openstack_networking_secgroup_v2.neutron_sg_os_private.id
    identity = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
  }
}

output "openstack_instance_ids" {
  value = {
    os_gateway      = openstack_compute_instance_v2.os_gateway.id
    os_k3s_master   = openstack_compute_instance_v2.os_k3s_master.id
    os_k3s_worker_1 = openstack_compute_instance_v2.os_k3s_worker_1.id
    os_k3s_worker_2 = openstack_compute_instance_v2.os_k3s_worker_2.id
    os_identity     = openstack_compute_instance_v2.os_identity.id
  }
}

output "os_gateway_floating_ip" {
  description = "Public floating IP used to SSH into os-gateway"
  value       = openstack_networking_floatingip_v2.os_gateway_fip.address
}

output "openstack_network_topology" {
  description = "OpenStack network topology for post-provision automation."
  value = {
    external_network = {
      id   = data.openstack_networking_network_v2.external.id
      name = data.openstack_networking_network_v2.external.name
    }
    dmz = {
      network_id = openstack_networking_network_v2.dmz.id
      subnet_id  = openstack_networking_subnet_v2.dmz_subnet.id
      cidr       = openstack_networking_subnet_v2.dmz_subnet.cidr
      gateway_ip = openstack_networking_subnet_v2.dmz_subnet.gateway_ip
    }
    private = {
      network_id = openstack_networking_network_v2.private.id
      subnet_id  = openstack_networking_subnet_v2.private_subnet.id
      cidr       = openstack_networking_subnet_v2.private_subnet.cidr
      gateway_ip = openstack_networking_subnet_v2.private_subnet.gateway_ip
    }
    identity = {
      network_id = openstack_networking_network_v2.identity.id
      subnet_id  = openstack_networking_subnet_v2.identity_subnet.id
      cidr       = openstack_networking_subnet_v2.identity_subnet.cidr
      gateway_ip = openstack_networking_subnet_v2.identity_subnet.gateway_ip
    }
    edge_router_id = openstack_networking_router_v2.edge_router.id
  }
}

output "openstack_security_groups" {
  description = "OpenStack security groups used by each zone."
  value = {
    dmz = {
      id   = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
      name = openstack_networking_secgroup_v2.neutron_sg_os_dmz.name
    }
    private = {
      id   = openstack_networking_secgroup_v2.neutron_sg_os_private.id
      name = openstack_networking_secgroup_v2.neutron_sg_os_private.name
    }
    identity = {
      id   = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
      name = openstack_networking_secgroup_v2.neutron_sg_os_identity.name
    }
  }
}

output "openstack_instances" {
  description = "Instance metadata and fixed IPs for inventory rendering."
  value = {
    os_gateway = {
      id        = openstack_compute_instance_v2.os_gateway.id
      public_ip = openstack_networking_floatingip_v2.os_gateway_fip.address
      networks = {
        dmz      = "192.168.100.10"
        private  = "192.168.101.1"
        identity = "192.168.102.1"
      }
      role = "wg-gateway"
    }
    os_k3s_master = {
      id         = openstack_compute_instance_v2.os_k3s_master.id
      private_ip = "192.168.101.11"
      role       = "k3s-master"
    }
    os_k3s_worker_1 = {
      id         = openstack_compute_instance_v2.os_k3s_worker_1.id
      private_ip = "192.168.101.12"
      role       = "k3s-worker"
    }
    os_k3s_worker_2 = {
      id         = openstack_compute_instance_v2.os_k3s_worker_2.id
      private_ip = "192.168.101.13"
      role       = "k3s-worker"
    }
    os_identity = {
      id          = openstack_compute_instance_v2.os_identity.id
      identity_ip = "192.168.102.10"
      role        = "identity"
    }
  }
}

output "openstack_k3s_api_tunnel" {
  description = "Data required to build local kubectl tunnel for OpenStack K3s API."
  value = {
    local_port         = 6443
    os_gateway_public  = openstack_networking_floatingip_v2.os_gateway_fip.address
    k3s_master_private = "192.168.101.11"
    api_server_port    = 6443
  }
}
