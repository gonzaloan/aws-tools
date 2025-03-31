#!/bin/bash

# subnets to test
SUBNET_IDS=("subnet-abc123" "subnet-def456" "subnet-ghi789")

LOG_GROUP="se-vpc-flowlogs"

IAM_ROLE_ARN="arn:aws:iam::123456789012:role/flow-logs-role"

# Create log group
aws logs create-log-group --log-group-name "$LOG_GROUP" 2>/dev/null

# Create flow logs for subnets
FLOW_LOG_ID=$(aws ec2 create-flow-logs \
  --resource-type Subnet \
  --resource-ids "${SUBNET_IDS[@]}" \
  --traffic-type ALL \
  --log-destination-type cloud-watch-logs \
  --log-group-name "$LOG_GROUP" \
  --deliver-logs-permission-arn "$IAM_ROLE_ARN" \
  --query 'FlowLogIds[0]' \
  --output text)


# --resource-type Subnet: subnet type.
#--resource-ids: aquí pones una o más subnets separadas por espacio.
#--traffic-type: ALL, ACCEPT, or REJECT).
#--deliver-logs-permission-arn: ARN IAM rol with permissions to send logs 

echo "Flow log created: $FLOW_LOG_ID"
echo "Check the log groups here: $LOG_GROUP"
echo "Waiting 5 minutes to test..."
sleep 300

# Delete flow logs
aws ec2 delete-flow-logs --flow-log-ids "$FLOW_LOG_ID"
echo "Flow log deleted."
