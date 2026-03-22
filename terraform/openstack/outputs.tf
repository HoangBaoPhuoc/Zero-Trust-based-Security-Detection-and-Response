output "os_project_name" {
  value = var.os_project_name
}

output "os_region" {
  value = var.os_region
}

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
