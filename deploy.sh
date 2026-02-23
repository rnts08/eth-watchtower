#!/bin/bash
# deploy.sh - Unified Cloud Deployment Script for ETH Watchtower
# Supports: Azure, GCP, AWS

set -e

# --- Default Variables ---
RESOURCE_PREFIX="eth-watch"
LOCATION_AZURE="eastus"
LOCATION_GCP="us-central1"
REGION_AWS="us-east-1"
TIMESTAMP=$(date +%s)

# --- Help Output ---
usage() {
    echo "Usage: $0 --provider {azure|gcp|aws} [options]"
    echo ""
    echo "Deploy ETH Watchtower to a serverless container environment with persistent storage."
    echo ""
    echo "Options:"
    echo "  --provider PROV    Cloud provider to use (azure, gcp, aws)"
    echo "  --prefix PREFIX    Prefix for resources (default: eth-watch)"
    echo "  --location LOC     Region/Location for deployment"
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --provider azure --location westeurope"
    echo "  $0 --provider gcp --prefix my-watcher"
    exit 1
}

# --- Azure Deployment ---
deploy_azure() {
    local PREFIX=$1
    local LOC=${2:-$LOCATION_AZURE}
    local RG="${PREFIX}-rg"
    local ACR="${PREFIX//-/}reg${TIMESTAMP}" # Alphanumeric only for ACR
    local STORAGE="${PREFIX//-/}store${TIMESTAMP}"
    local SHARE="watchtower-data"
    local ENV="${PREFIX}-env"
    local APP="${PREFIX}-app"

    echo "🚀 Starting Azure Deployment..."
    echo "Resource Group: $RG"
    echo "Location: $LOC"

    az group create --name "$RG" --location "$LOC"
    az acr create --resource-group "$RG" --name "$ACR" --sku Basic
    
    ACR_LOGIN_SERVER=$(az acr show --resource-group "$RG" --name "$ACR" --query loginServer --output tsv)
    az acr login --resource-group "$RG" --name "$ACR"

    echo "📦 Building and Pushing Image..."
    docker build -t "$ACR_LOGIN_SERVER/eth-watchtower:latest" .
    docker push "$ACR_LOGIN_SERVER/eth-watchtower:latest"

    echo "💾 Setting up Storage..."
    az storage account create --name "$STORAGE" --resource-group "$RG" --location "$LOC" --sku Standard_LRS
    STORAGE_KEY=$(az storage account keys list --resource-group "$RG" --account-name "$STORAGE" --query "[0].value" --output tsv)
    az storage share create --name "$SHARE" --account-name "$STORAGE" --account-key "$STORAGE_KEY"

    echo "☁️  Creating Container App Environment..."
    az containerapp env create --name "$ENV" --resource-group "$RG" --location "$LOC"
    az containerapp env storage set \
        --name "$ENV" \
        --resource-group "$RG" \
        --storage-name "$SHARE" \
        --azure-file-account-name "$STORAGE" \
        --azure-file-account-key "$STORAGE_KEY" \
        --azure-file-share-name "$SHARE" \
        --access-mode ReadWrite

    az acr update --name "$ACR" --resource-group "$RG" --admin-enabled true
    ACR_USERNAME=$(az acr credential show --name "$ACR" --resource-group "$RG" --query username -o tsv)
    ACR_PASSWORD=$(az acr credential show --name "$ACR" --resource-group "$RG" --query "passwords[0].value" -o tsv)
    
    SUBSCRIPTION_ID=$(az account show --query id -o tsv)
    ENV_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RG/providers/Microsoft.App/managedEnvironments/$ENV"

    echo "📄 Generating Deployment YAML..."
    cat <<EOF > aca-deploy.yaml
name: $APP
location: $LOC
type: Microsoft.App/containerApps
properties:
  managedEnvironmentId: $ENV_ID
  configuration:
    ingress:
      external: true
      targetPort: 2112
      allowInsecure: false
      transport: auto
    registries:
      - server: $ACR_LOGIN_SERVER
        username: $ACR_USERNAME
        passwordSecretRef: acr-password
    secrets:
      - name: acr-password
        value: $ACR_PASSWORD
  template:
    containers:
      - image: $ACR_LOGIN_SERVER/eth-watchtower:latest
        name: eth-watchtower
        args:
          - "-config"
          - "/app/config.json"
          - "-data"
          - "/app/data"
          - "-auth"
          - "ethwatchtower:ethwatchtower"
        resources:
          cpu: "0.5"
          memory: "1.0Gi"
        volumeMounts:
          - volumeName: watchtower-data
            mountPath: /app/data
    volumes:
      - name: watchtower-data
        storageName: $SHARE
        storageType: AzureFile
EOF

    echo "🏗️  Deploying Container App via YAML..."
    az containerapp create \
        --resource-group "$RG" \
        --yaml aca-deploy.yaml

    rm aca-deploy.yaml
    echo "✅ Azure Deployment Complete!"
    az containerapp show --name "$APP" --resource-group "$RG" --query properties.configuration.ingress.fqdn --output tsv
}

# --- GCP Deployment ---
deploy_gcp() {
    local PREFIX=$1
    local LOC=${2:-$LOCATION_GCP}
    local PROJECT_ID=$(gcloud config get-value project)
    local REPO="${PREFIX}-repo"
    local BUCKET="${PREFIX}-data-${TIMESTAMP}"
    local SERVICE="${PREFIX}-service"
    local SA="${PREFIX}-sa"

    echo "🚀 Starting GCP Deployment..."
    echo "Project: $PROJECT_ID"
    echo "Location: $LOC"

    gcloud services enable artifactregistry.googleapis.com run.googleapis.com storage.googleapis.com

    gcloud artifacts repositories create "$REPO" \
        --repository-format=docker \
        --location="$LOC" \
        --description="Docker repository for ETH Watchtower" || true

    IMAGE_TAG="$LOC-docker.pkg.dev/$PROJECT_ID/$REPO/eth-watchtower:latest"
    
    echo "📦 Building and Pushing Image (via Cloud Build)..."
    gcloud builds submit --tag "$IMAGE_TAG" .

    echo "💾 Setting up Cloud Storage..."
    gsutil mb -l "$LOC" "gs://$BUCKET"

    echo "🔑 Configuring Service Account..."
    gcloud iam service-accounts create "$SA" --display-name="Service Account for ETH Watchtower" || true
    gcloud storage buckets add-iam-policy-binding "gs://$BUCKET" \
        --member="serviceAccount:$SA@$PROJECT_ID.iam.gserviceaccount.com" \
        --role="roles/storage.objectAdmin"

    echo "🏗️  Deploying to Cloud Run..."
    gcloud run deploy "$SERVICE" \
        --image "$IMAGE_TAG" \
        --region "$LOC" \
        --service-account "$SA@$PROJECT_ID.iam.gserviceaccount.com" \
        --add-volume="name=watchtower-data,type=cloud-storage,bucket=$BUCKET" \
        --add-volume-mount="volume=watchtower-data,mount-path=/app/data" \
        --args="-config","/app/config.json","-data","/app/data","-auth","ethwatchtower:ethwatchtower" \
        --port=2112 \
        --allow-unauthenticated \
        --min-instances=1

    echo "✅ GCP Deployment Complete!"
    gcloud run services describe "$SERVICE" --region "$LOC" --format='value(status.url)'
}

# --- AWS Deployment ---
deploy_aws() {
    local PREFIX=$1
    local LOC=${2:-$REGION_AWS}
    local ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output tsv)
    local REPO="${PREFIX}-repo"
    local CLUSTER="${PREFIX}-cluster"
    local TASK_FAMILY="${PREFIX}-task"
    local VPC_ID=$(aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output tsv)
    local SUBNET_ID=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$VPC_ID" --query "Subnets[0].SubnetId" --output tsv)
    local SG_ID=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$VPC_ID" "Name=group-name,Values=default" --query "SecurityGroups[0].GroupId" --output tsv)

    echo "🚀 Starting AWS Deployment..."
    echo "Account: $ACCOUNT_ID"
    echo "Region: $LOC"

    echo "📦 Setting up ECR..."
    aws ecr create-repository --repository-name "$REPO" --region "$LOC" || true
    IMAGE_TAG="$ACCOUNT_ID.dkr.ecr.$LOC.amazonaws.com/$REPO:latest"
    
    aws ecr get-login-password --region "$LOC" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$LOC.amazonaws.com"
    docker build -t "$REPO" .
    docker tag "$REPO:latest" "$IMAGE_TAG"
    docker push "$IMAGE_TAG"

    echo "💾 Setting up EFS..."
    FILE_SYSTEM_ID=$(aws efs create-file-system --creation-token "${PREFIX}-efs" --region "$LOC" --query FileSystemId --output tsv)
    
    # Wait for FS to be available
    echo "Waiting for EFS to be available..."
    while [[ $(aws efs describe-file-systems --file-system-id "$FILE_SYSTEM_ID" --region "$LOC" --query "FileSystems[0].LifeCycleState" --output tsv) != "available" ]]; do
        sleep 5
    done
    
    aws efs create-mount-target --file-system-id "$FILE_SYSTEM_ID" --subnet-id "$SUBNET_ID" --security-groups "$SG_ID" --region "$LOC"

    echo "🏗️  Creating ECS Infrastructure..."
    aws ecs create-cluster --cluster-name "$CLUSTER" --region "$LOC"

    echo "📄 Registering Task Definition..."
    cat <<EOF > task-definition.json
{
  "family": "$TASK_FAMILY",
  "networkMode": "awsvpc",
  "containerDefinitions": [
    {
      "name": "eth-watchtower",
      "image": "$IMAGE_TAG",
      "essential": true,
      "command": ["-config", "/app/config.json", "-data", "/app/data", "-auth", "ethwatchtower:ethwatchtower"],
      "portMappings": [
        { "containerPort": 2112, "hostPort": 2112, "protocol": "tcp" }
      ],
      "mountPoints": [
        { "sourceVolume": "watchtower-data", "containerPath": "/app/data", "readOnly": false }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/$TASK_FAMILY",
          "awslogs-region": "$LOC",
          "awslogs-stream-prefix": "ecs",
          "awslogs-create-group": "true"
        }
      }
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

    aws ecs register-task-definition --cli-input-json file://task-definition.json --region "$LOC"

    echo "🚀 Starting ECS Service..."
    aws ecs create-service \
        --cluster "$CLUSTER" \
        --service-name "${PREFIX}-service" \
        --task-definition "$TASK_FAMILY" \
        --desired-count 1 \
        --launch-type FARGATE \
        --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_ID],assignPublicIp=ENABLED,securityGroups=[$SG_ID]}" \
        --region "$LOC"

    echo "✅ AWS Deployment Complete!"
}

# --- Main Logic ---

PROVIDER=""
PREFIX=$RESOURCE_PREFIX
LOCATION=""

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --provider) PROVIDER="$2"; shift ;;
        --prefix) PREFIX="$2"; shift ;;
        --location|--region) LOCATION="$2"; shift ;;
        --help) usage ;;
        *) echo "Unknown parameter: $1"; usage ;;
    esac
    shift
done

if [[ -z "$PROVIDER" ]]; then
    echo "Error: --provider is required."
    usage
fi

case $PROVIDER in
    azure) deploy_azure "$PREFIX" "$LOCATION" ;;
    gcp)   deploy_gcp   "$PREFIX" "$LOCATION" ;;
    aws)   deploy_aws   "$PREFIX" "$LOCATION" ;;
    *)     echo "Error: Invalid provider '$PROVIDER'. Use azure, gcp, or aws."; exit 1 ;;
esac
