output "aws_gateway_eip" {
  value = aws_eip.wg_gateway.public_ip
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
    siem_1     = aws_instance.aws_siem_1.private_ip
    siem_2     = aws_instance.aws_siem_2.private_ip
    opensearch = aws_instance.aws_opensearch.private_ip
    soar       = aws_instance.aws_soar.private_ip
    ai         = aws_instance.aws_ai.private_ip
  }
}

output "aws_management_nodes" {
  value = {
    bastion    = aws_instance.aws_bastion.private_ip
    iac_runner = aws_instance.aws_iac_runner.private_ip
  }
}

output "aws_vpc_id" {
  value = aws_vpc.ztlab.id
}
