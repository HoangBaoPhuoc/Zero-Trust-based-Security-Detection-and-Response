output "aws_gateway_eip" {
  value = aws_eip.wg_gateway.public_ip
}

output "aws_bastion_pip" {
  value = aws_instance.aws_bastion.public_ip
}

output "aws_gateway_private_ip" {
  value = aws_instance.aws_gateway.private_ip
}

output "aws_private_nodes" {
  value = {
    k3s_master   = aws_instance.aws_k3s_master.private_ip
    k3s_worker_1 = aws_instance.aws_k3s_worker_1.private_ip
    k3s_worker_2 = aws_instance.aws_k3s_worker_2.private_ip
    security     = aws_instance.aws_security.private_ip
  }
}

output "aws_restricted_nodes" {
  value = {
    siem = aws_instance.aws_siem.private_ip
  }
}

output "aws_management_nodes" {
  value = {
    bastion = aws_instance.aws_bastion.private_ip
  }
}

output "aws_vpc_id" {
  value = aws_vpc.ztlab.id
}

output "aws_network_topology" {
  description = "AWS network IDs and CIDRs for downstream automation."
  value = {
    region = var.aws_region
    vpc = {
      id   = aws_vpc.ztlab.id
      cidr = var.vpc_cidr
    }
    internet_gateway_id = aws_internet_gateway.ztlab.id
    public_route_table  = aws_route_table.public.id
    subnets = {
      dmz = {
        id   = aws_subnet.dmz.id
        cidr = var.dmz_subnet_cidr
        az   = aws_subnet.dmz.availability_zone
      }
      private = {
        id   = aws_subnet.private.id
        cidr = var.private_subnet_cidr
        az   = aws_subnet.private.availability_zone
      }
      restricted_a = {
        id   = aws_subnet.restricted_a.id
        cidr = var.restricted_a_subnet_cidr
        az   = aws_subnet.restricted_a.availability_zone
      }
      restricted_b = {
        id   = aws_subnet.restricted_b.id
        cidr = var.restricted_b_subnet_cidr
        az   = aws_subnet.restricted_b.availability_zone
      }
      management = {
        id   = aws_subnet.management.id
        cidr = var.management_subnet_cidr
        az   = aws_subnet.management.availability_zone
      }
    }
  }
}

output "aws_security_groups" {
  description = "Security group IDs used by each zone."
  value = {
    dmz        = aws_security_group.sg_dmz.id
    private    = aws_security_group.sg_private.id
    restricted = aws_security_group.sg_restricted.id
    management = aws_security_group.sg_management.id
  }
}

output "aws_instances" {
  description = "Instance metadata for inventory generation and post-provisioning scripts."
  value = {
    aws_gateway = {
      id         = aws_instance.aws_gateway.id
      private_ip = aws_instance.aws_gateway.private_ip
      elastic_ip = aws_eip.wg_gateway.public_ip
      public_ip  = aws_instance.aws_gateway.public_ip
      subnet_id  = aws_subnet.dmz.id
      role       = "wg-server"
    }
    aws_k3s_master = {
      id         = aws_instance.aws_k3s_master.id
      private_ip = aws_instance.aws_k3s_master.private_ip
      subnet_id  = aws_subnet.private.id
      role       = "k3s-master"
    }
    aws_k3s_worker_1 = {
      id         = aws_instance.aws_k3s_worker_1.id
      private_ip = aws_instance.aws_k3s_worker_1.private_ip
      subnet_id  = aws_subnet.private.id
      role       = "k3s-worker"
    }
    aws_k3s_worker_2 = {
      id         = aws_instance.aws_k3s_worker_2.id
      private_ip = aws_instance.aws_k3s_worker_2.private_ip
      subnet_id  = aws_subnet.private.id
      role       = "k3s-worker"
    }
    aws_security = {
      id         = aws_instance.aws_security.id
      private_ip = aws_instance.aws_security.private_ip
      subnet_id  = aws_subnet.private.id
      role       = "spire-keycloak"
    }
    aws_siem = {
      id         = aws_instance.aws_siem.id
      private_ip = aws_instance.aws_siem.private_ip
      subnet_id  = aws_subnet.restricted_a.id
      role       = "siem"
    }
    aws_bastion = {
      id         = aws_instance.aws_bastion.id
      private_ip = aws_instance.aws_bastion.private_ip
      public_ip  = aws_instance.aws_bastion.public_ip
      subnet_id  = aws_subnet.management.id
      role       = "bastion"
    }
  }
}

output "aws_wireguard_bootstrap" {
  description = "WireGuard gateway details commonly consumed by bootstrap scripts."
  value = {
    gateway_instance_id = aws_instance.aws_gateway.id
    gateway_private_ip  = aws_instance.aws_gateway.private_ip
    gateway_public_ip   = aws_eip.wg_gateway.public_ip
    eip_allocation_id   = aws_eip.wg_gateway.id
  }
}

output "aws_k3s_api_tunnel" {
  description = "Data required to build local kubectl tunnel for AWS K3s API."
  value = {
    local_port         = 6444
    bastion_public_ip  = aws_instance.aws_bastion.public_ip
    k3s_master_private = aws_instance.aws_k3s_master.private_ip
    api_server_port    = 6443
  }
}

output "aws_apply_context" {
  description = "Resolved settings used for deployment and follow-up automation."
  value = {
    region            = var.aws_region
    availability_zone = local.primary_az
    key_pair_name     = local.effective_key_pair
    key_pair_mode     = var.create_key_pair ? "managed-by-terraform" : "pre-existing"
  }
}
