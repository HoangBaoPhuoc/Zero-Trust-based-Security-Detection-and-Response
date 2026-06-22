# DMZ Security Group
resource "openstack_networking_secgroup_v2" "neutron_sg_os_dmz" {
  name        = "neutron-sg-os-dmz"
  description = "DMZ security group for OpenStack"
}

resource "openstack_networking_secgroup_rule_v2" "os_dmz_ingress_from_external" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
}

resource "openstack_networking_secgroup_rule_v2" "os_dmz_ingress_ssh_from_aio" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = var.aio_provider_cidr
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
}

resource "openstack_networking_secgroup_rule_v2" "os_dmz_ingress_wireguard" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 51820
  port_range_max    = 51820
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_dmz.id
  description       = "WireGuard cross-cloud VPN from aws_gateway"
}

# Private Security Group 
resource "openstack_networking_secgroup_v2" "neutron_sg_os_private" {
  name        = "neutron-sg-os-private"
  description = "Private security group for OpenStack K3s cluster"
}

resource "openstack_networking_secgroup_rule_v2" "os_private_ingress_k3s" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 6443
  port_range_max    = 6443
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_ingress_kubelet" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 10250
  port_range_max    = 10250
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_ingress_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_ingress_ssh_from_gateway" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "192.168.101.1/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
  description       = "Allow SSH from os_gateway private interface"
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_loki" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3100
  port_range_max    = 3100
  remote_ip_prefix  = "10.10.2.10/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
  description       = "Loki log collection (via WireGuard cross-cloud tunnel)"
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

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_k3s_api_aws" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 6443
  port_range_max    = 6443
  remote_ip_prefix  = "10.10.1.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_dns" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_http_https" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

resource "openstack_networking_secgroup_rule_v2" "os_private_egress_https" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_private.id
}

# Identity Security Group
resource "openstack_networking_secgroup_v2" "neutron_sg_os_identity" {
  name        = "neutron-sg-os-identity"
  description = "Identity security group"
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_private_dns" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_private_udp_dns" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_private_icmp" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "icmp"
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_ingress_ssh_from_gateway" {
  direction         = "ingress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 22
  port_range_max    = 22
  remote_ip_prefix  = "192.168.102.1/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
  description       = "Allow SSH from os_gateway identity interface"
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_egress_spire" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 8081
  port_range_max    = 8081
  remote_ip_prefix  = "10.10.1.20/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_egress_loki" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 3100
  port_range_max    = 3100
  remote_ip_prefix  = "10.10.2.10/32"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
  description       = "Loki log collection (via WireGuard cross-cloud tunnel)"
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_egress_kubelet_attestation" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 10250
  port_range_max    = 10250
  remote_ip_prefix  = "192.168.101.0/24"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_egress_dns" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "udp"
  port_range_min    = 53
  port_range_max    = 53
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_egress_http_https" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 80
  port_range_max    = 80
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}

resource "openstack_networking_secgroup_rule_v2" "os_identity_egress_https" {
  direction         = "egress"
  ethertype         = "IPv4"
  protocol          = "tcp"
  port_range_min    = 443
  port_range_max    = 443
  remote_ip_prefix  = "0.0.0.0/0"
  security_group_id = openstack_networking_secgroup_v2.neutron_sg_os_identity.id
}
