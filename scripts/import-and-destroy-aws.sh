#!/usr/bin/env bash
set -euo pipefail

# Import existing AWS resources back into terraform/aws state and optionally destroy them.
# Usage:
#   ./scripts/import-and-destroy-aws.sh            # import + destroy
#   ./scripts/import-and-destroy-aws.sh --no-destroy
#
# Optional env:
#   TF_AWS_DIR=/etc/zta-siem-soar/terraform/aws
#   AWS_PROFILE=default
#   AWS_REGION=ap-southeast-1

TF_AWS_DIR="${TF_AWS_DIR:-/etc/zta-siem-soar/terraform/aws}"
DO_DESTROY=1

if [[ "${1:-}" == "--no-destroy" ]]; then
  DO_DESTROY=0
fi

if [[ ! -d "$TF_AWS_DIR" ]]; then
  echo "[ERROR] terraform/aws directory not found: $TF_AWS_DIR" >&2
  exit 1
fi

if ! command -v terraform >/dev/null 2>&1; then
  echo "[ERROR] terraform not found" >&2
  exit 1
fi
if ! command -v aws >/dev/null 2>&1; then
  echo "[ERROR] aws cli not found" >&2
  exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
  echo "[ERROR] jq not found" >&2
  exit 1
fi

cd "$TF_AWS_DIR"

if [[ -z "${AWS_REGION:-}" ]]; then
  AWS_REGION="$(awk -F'=' '/^aws_region/{gsub(/[ "\t]/, "", $2); print $2; exit}' terraform.tfvars 2>/dev/null || true)"
fi
AWS_REGION="${AWS_REGION:-ap-southeast-1}"
export AWS_REGION

if [[ -z "${AWS_PROFILE:-}" ]]; then
  PROFILE_FROM_TFVARS="$(awk -F'=' '/^aws_profile/{gsub(/[ "\t]/, "", $2); print $2; exit}' terraform.tfvars 2>/dev/null || true)"
  if [[ -n "$PROFILE_FROM_TFVARS" && "$PROFILE_FROM_TFVARS" != "null" ]]; then
    export AWS_PROFILE="$PROFILE_FROM_TFVARS"
  fi
fi

echo "[INFO] Working dir: $TF_AWS_DIR"
echo "[INFO] AWS_REGION=$AWS_REGION"
echo "[INFO] AWS_PROFILE=${AWS_PROFILE:-<unset>}"

echo "[INFO] Checking AWS credentials..."
aws sts get-caller-identity --output json >/dev/null

echo "[INFO] terraform init..."
terraform init -input=false >/dev/null

state_has() {
  local addr="$1"
  terraform state show "$addr" >/dev/null 2>&1
}

import_if_missing() {
  local addr="$1"
  local id="$2"
  if [[ -z "$id" || "$id" == "null" ]]; then
    echo "[WARN] Skip $addr (id is empty)"
    return 0
  fi
  if state_has "$addr"; then
    echo "[SKIP] $addr already in state"
    return 0
  fi
  echo "[IMPORT] $addr <= $id"
  terraform import "$addr" "$id"
}

# Resolve IDs
VPC_ID="$(aws ec2 describe-vpcs --filters Name=tag:Name,Values=ztlab-vpc --region "$AWS_REGION" --output json | jq -r '.Vpcs[0].VpcId // empty')"
if [[ -z "$VPC_ID" ]]; then
  echo "[ERROR] Cannot find VPC by tag Name=ztlab-vpc in region $AWS_REGION" >&2
  exit 1
fi

IGW_ID="$(aws ec2 describe-internet-gateways --filters Name=attachment.vpc-id,Values="$VPC_ID" --region "$AWS_REGION" --output json | jq -r '.InternetGateways[0].InternetGatewayId // empty')"
SUBNET_DMZ_ID="$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values=ztlab-dmz --region "$AWS_REGION" --output json | jq -r '.Subnets[0].SubnetId // empty')"
SUBNET_PRIVATE_ID="$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values=ztlab-private --region "$AWS_REGION" --output json | jq -r '.Subnets[0].SubnetId // empty')"
SUBNET_RESA_ID="$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values=ztlab-restricted-a --region "$AWS_REGION" --output json | jq -r '.Subnets[0].SubnetId // empty')"
SUBNET_RESB_ID="$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values=ztlab-restricted-b --region "$AWS_REGION" --output json | jq -r '.Subnets[0].SubnetId // empty')"
SUBNET_MGMT_ID="$(aws ec2 describe-subnets --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values=ztlab-management --region "$AWS_REGION" --output json | jq -r '.Subnets[0].SubnetId // empty')"

RT_PUBLIC_ID="$(aws ec2 describe-route-tables --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values=ztlab-public-rt --region "$AWS_REGION" --output json | jq -r '.RouteTables[0].RouteTableId // empty')"
RT_PRIVATE_EGRESS_ID="$(aws ec2 describe-route-tables --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values=ztlab-private-egress-rt --region "$AWS_REGION" --output json | jq -r '.RouteTables[0].RouteTableId // empty')"

# aws_route_table_association import format is:
#   subnet-id/route-table-id   or   gateway-id/route-table-id
ASSOC_DMZ_ID="${SUBNET_DMZ_ID}/${RT_PUBLIC_ID}"
ASSOC_MGMT_ID="${SUBNET_MGMT_ID}/${RT_PUBLIC_ID}"
ASSOC_PRIVATE_ID="${SUBNET_PRIVATE_ID}/${RT_PRIVATE_EGRESS_ID}"
ASSOC_RESA_ID="${SUBNET_RESA_ID}/${RT_PRIVATE_EGRESS_ID}"
ASSOC_RESB_ID="${SUBNET_RESB_ID}/${RT_PRIVATE_EGRESS_ID}"

EIP_ALLOC_ID="$(aws ec2 describe-addresses --filters Name=tag:Name,Values=ztlab-wg-gateway-eip --region "$AWS_REGION" --output json | jq -r '.Addresses[0].AllocationId // empty')"
EIP_ASSOC_ID="$(aws ec2 describe-addresses --allocation-ids "$EIP_ALLOC_ID" --region "$AWS_REGION" --output json 2>/dev/null | jq -r '.Addresses[0].AssociationId // empty')"

instance_id_by_name() {
  local n="$1"
  aws ec2 describe-instances \
    --filters Name=vpc-id,Values="$VPC_ID" Name=tag:Name,Values="$n" Name=instance-state-name,Values=pending,running,stopping,stopped \
    --region "$AWS_REGION" --output json \
    | jq -r '.Reservations[].Instances[]?.InstanceId' | head -n1
}

INSTANCE_AWS_GATEWAY_ID="$(instance_id_by_name aws-gateway)"
INSTANCE_AWS_K3S_MASTER_ID="$(instance_id_by_name aws-k3s-master)"
INSTANCE_AWS_K3S_WORKER_1_ID="$(instance_id_by_name aws-k3s-worker-1)"
INSTANCE_AWS_K3S_WORKER_2_ID="$(instance_id_by_name aws-k3s-worker-2)"
INSTANCE_AWS_SECURITY_ID="$(instance_id_by_name aws-security)"
INSTANCE_AWS_SIEM_1_ID="$(instance_id_by_name aws-siem-1)"
INSTANCE_AWS_SIEM_2_ID="$(instance_id_by_name aws-siem-2)"
INSTANCE_AWS_OPENSEARCH_ID="$(instance_id_by_name aws-opensearch)"
INSTANCE_AWS_SOAR_ID="$(instance_id_by_name aws-soar)"
INSTANCE_AWS_AI_ID="$(instance_id_by_name aws-ai)"
INSTANCE_AWS_BASTION_ID="$(instance_id_by_name aws-bastion)"

SG_DMZ_ID="$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC_ID" Name=group-name,Values=ztlab-sg-dmz --region "$AWS_REGION" --output json | jq -r '.SecurityGroups[0].GroupId // empty')"
SG_PRIVATE_ID="$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC_ID" Name=group-name,Values=ztlab-sg-private --region "$AWS_REGION" --output json | jq -r '.SecurityGroups[0].GroupId // empty')"
SG_RESTRICTED_ID="$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC_ID" Name=group-name,Values=ztlab-sg-restricted --region "$AWS_REGION" --output json | jq -r '.SecurityGroups[0].GroupId // empty')"
SG_MANAGEMENT_ID="$(aws ec2 describe-security-groups --filters Name=vpc-id,Values="$VPC_ID" Name=group-name,Values=ztlab-sg-management --region "$AWS_REGION" --output json | jq -r '.SecurityGroups[0].GroupId // empty')"

KEY_NAME="$(aws ec2 describe-key-pairs --key-names ztlab-key --region "$AWS_REGION" --output json 2>/dev/null | jq -r '.KeyPairs[0].KeyName // empty')"

# Import core network
import_if_missing aws_vpc.ztlab "$VPC_ID"
import_if_missing aws_internet_gateway.ztlab "$IGW_ID"
import_if_missing aws_subnet.dmz "$SUBNET_DMZ_ID"
import_if_missing aws_subnet.private "$SUBNET_PRIVATE_ID"
import_if_missing aws_subnet.restricted_a "$SUBNET_RESA_ID"
import_if_missing aws_subnet.restricted_b "$SUBNET_RESB_ID"
import_if_missing aws_subnet.management "$SUBNET_MGMT_ID"
import_if_missing aws_route_table.public "$RT_PUBLIC_ID"
import_if_missing aws_route_table.private_egress "$RT_PRIVATE_EGRESS_ID"
import_if_missing aws_route_table_association.dmz "$ASSOC_DMZ_ID"
import_if_missing aws_route_table_association.management "$ASSOC_MGMT_ID"
import_if_missing aws_route_table_association.private "$ASSOC_PRIVATE_ID"
import_if_missing aws_route_table_association.restricted_a "$ASSOC_RESA_ID"
import_if_missing aws_route_table_association.restricted_b "$ASSOC_RESB_ID"

# Import security groups
import_if_missing aws_security_group.sg_dmz "$SG_DMZ_ID"
import_if_missing aws_security_group.sg_private "$SG_PRIVATE_ID"
import_if_missing aws_security_group.sg_restricted "$SG_RESTRICTED_ID"
import_if_missing aws_security_group.sg_management "$SG_MANAGEMENT_ID"

# Import key pair and EIP resources
import_if_missing 'aws_key_pair.ztlab[0]' "$KEY_NAME"
import_if_missing aws_eip.wg_gateway "$EIP_ALLOC_ID"
import_if_missing aws_eip_association.wg_eip_assoc "$EIP_ASSOC_ID"

# Import instances
import_if_missing aws_instance.aws_gateway "$INSTANCE_AWS_GATEWAY_ID"
import_if_missing aws_instance.aws_k3s_master "$INSTANCE_AWS_K3S_MASTER_ID"
import_if_missing aws_instance.aws_k3s_worker_1 "$INSTANCE_AWS_K3S_WORKER_1_ID"
import_if_missing aws_instance.aws_k3s_worker_2 "$INSTANCE_AWS_K3S_WORKER_2_ID"
import_if_missing aws_instance.aws_security "$INSTANCE_AWS_SECURITY_ID"
import_if_missing aws_instance.aws_siem_1 "$INSTANCE_AWS_SIEM_1_ID"
import_if_missing aws_instance.aws_siem_2 "$INSTANCE_AWS_SIEM_2_ID"
import_if_missing aws_instance.aws_opensearch "$INSTANCE_AWS_OPENSEARCH_ID"
import_if_missing aws_instance.aws_soar "$INSTANCE_AWS_SOAR_ID"
import_if_missing aws_instance.aws_ai "$INSTANCE_AWS_AI_ID"
import_if_missing aws_instance.aws_bastion "$INSTANCE_AWS_BASTION_ID"

echo "[INFO] Imported resources now in state:"
terraform state list || true

echo "[INFO] terraform plan -destroy (preview)"
terraform plan -destroy -out=tfplan-destroy

if [[ "$DO_DESTROY" -eq 1 ]]; then
  echo "[INFO] terraform destroy --auto-approve"
  terraform destroy --auto-approve
else
  echo "[INFO] Skip destroy due to --no-destroy"
fi
