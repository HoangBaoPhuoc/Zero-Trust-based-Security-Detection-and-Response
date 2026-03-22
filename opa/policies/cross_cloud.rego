package zta.cross_cloud

default allow_cross_cloud = false

allow_cross_cloud {
  input.source.principal == "spiffe://ztlab.local/aws/payment-service"
  input.destination.principal == "spiffe://ztlab.local/os/core-banking"
}

# TODO: populate from IMPLEMENTATION.md §5.2
