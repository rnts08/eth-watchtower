# AWS Deployment Guide: ETH Watchtower

This guide details how to deploy ETH Watchtower to **Amazon ECS (Fargate)** with persistent output to **Amazon EFS** (Elastic File System) using the `aws` CLI.

## Prerequisites

- [AWS CLI](https://aws.amazon.com/cli/) installed and configured (`aws configure`).
- Docker installed locally.

## Deployment Steps

### 1. Set Environment Variables

```bash
REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output tsv)
REPO_NAME="eth-watchtower"
CLUSTER_NAME="eth-watcher-cluster"
TASK_FAMILY="eth-watchtower-task"
VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output tsv)
SUBNET_ID=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query "Subnets[0].SubnetId" --output tsv)
```

### 2. Setup Elastic Container Registry (ECR)

```bash
# Create ECR repository
aws ecr create-repository --repository-name $REPO_NAME --region $REGION

# Login to ECR
aws ecr get-login-password --region $REGION | docker login --username AWS --password-stdin $ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com
```

### 3. Build and Push Image

```bash
IMAGE_TAG="$ACCOUNT_ID.dkr.ecr.$REGION.amazonaws.com/$REPO_NAME:latest"

docker build -t $REPO_NAME .
docker tag $REPO_NAME:latest $IMAGE_TAG
docker push $IMAGE_TAG
```

### 4. Setup Persistent Storage (EFS)

Fargate uses EFS for persistent file storage.

```bash
# Create File System
FILE_SYSTEM_ID=$(aws efs create-file-system --creation-token eth-watchtower-efs --region $REGION --query FileSystemId --output tsv)

# Create Mount Target (Wait for FS to be 'available' first)
aws efs create-mount-target --file-system-id $FILE_SYSTEM_ID --subnet-id $SUBNET_ID --security-groups $(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=default" --query "SecurityGroups[0].GroupId" --output tsv)
```

### 5. Create ECS Infrastructure

```bash
# Create Cluster
aws ecs create-cluster --cluster-name $CLUSTER_NAME --region $REGION
```

### 6. Register Task Definition

You'll need a `task-definition.json` representing your container.

```bash
cat <<EOF > task-definition.json
{
  "family": "$TASK_FAMILY",
  "networkMode": "awsvpc",
  "containerDefinitions": [
    {
      "name": "eth-watchtower",
      "image": "$IMAGE_TAG",
      "essential": true,
      "command": ["-config", "/app/config.json"],
      "portMappings": [
        { "containerPort": 2112, "hostPort": 2112, "protocol": "tcp" }
      ],
      "mountPoints": [
        { "sourceVolume": "watchtower-data", "containerPath": "/app/data", "readOnly": false }
      ]
    }
  ],
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "volumes": [
    {
      "name": "watchtower-data",
      "efsVolumeConfiguration": {
        "fileSystemId": "$FILE_SYSTEM_ID",
        "rootDirectory": "/"
      }
    }
  ],
  "executionRoleArn": "arn:aws:iam::$ACCOUNT_ID:role/ecsTaskExecutionRole"
}
EOF

aws ecs register-task-definition --cli-input-json file://task-definition.json
```

### 7. Run the Service

```bash
aws ecs create-service \
    --cluster $CLUSTER_NAME \
    --service-name eth-watchtower-service \
    --task-definition $TASK_FAMILY \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_ID],assignPublicIp=ENABLED,securityGroups=[$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=default" --query "SecurityGroups[0].GroupId" --output tsv)]}"
```

## Accessing Logs and Data

Persistent data and logs are available via either EFS mounting or the integrated web server.

### 1. Web Access (Secure)
Access the logs in your browser using the Task's public IP at the `/data/` endpoint (ensure port 2112 is open in your security group):
- **URL**: `http://<public-ip>:2112/data/`
- **Username**: `ethwatchtower`
- **Password**: `ethwatchtower`

### 2. EFS Access
Data is persisted on EFS. To access it, you can mount the EFS to an EC2 instance or use AWS Transfer Family.

## Monitoring

Metrics are available on port 2112. You can configure an AWS Load Balancer to expose this or use CloudWatch Container Insights.
