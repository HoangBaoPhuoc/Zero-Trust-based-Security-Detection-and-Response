aws_region         = "ap-southeast-1"
admin_ip           = "0.0.0.0/0"
gateway_private_ip = "10.10.0.10"

# Let Terraform create/import the EC2 key pair to avoid InvalidKeyPair.NotFound.
create_key_pair = true
key_pair_name   = "ztlab-key"
public_key_path = "~/.ssh/id_rsa.pub"

# Free-tier-friendly defaults for newer AWS accounts.
instance_type_gateway    = "t3.micro"
instance_type_k3s_master = "t3.medium"
instance_type_k3s_worker = "t3.small"
instance_type_security   = "t3.micro"
instance_type_siem       = "t3.medium"
instance_type_bastion    = "t3.micro"
