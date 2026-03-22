resource "openstack_networking_secgroup_v2" "neutron_sg_os_dmz" {
  name        = "neutron-sg-os-dmz"
  description = "OpenStack DMZ security group"
}

resource "openstack_networking_secgroup_v2" "neutron_sg_os_private" {
  name        = "neutron-sg-os-private"
  description = "OpenStack private security group"
}

resource "openstack_networking_secgroup_v2" "neutron_sg_os_identity" {
  name        = "neutron-sg-os-identity"
  description = "OpenStack identity security group"
}

resource "openstack_networking_secgroup_rule_v2" "os_dmz_egress_wireguard" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 51820
  port_range_max    = 51820
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
}

resource "openstack_networking_secgroup_rule_v2" "os_dmz_ingress_internal_tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
}

resource "openstack_networking_secgroup_rule_v2" "os_dmz_ingress_identity_tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  remote_ip_prefix  = "192.168.102.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_ingress_k3s_nodes" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_dmz_tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  remote_ip_prefix  = "192.168.100.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_private_tcp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_dmz_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = "192.168.100.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_private_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_logstash" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 5044
  port_range_max    = 5044
  remote_ip_prefix  = "10.10.2.11/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_wazuh" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 1514
  port_range_max    = 1514
  remote_ip_prefix  = "10.10.2.10/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_kafka" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 9092
  port_range_max    = 9092
  remote_ip_prefix  = "10.10.2.11/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_spire" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8081
  port_range_max    = 8081
  remote_ip_prefix  = "10.10.1.20/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}
