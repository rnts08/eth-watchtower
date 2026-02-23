#!/bin/bash
# deploy.sh - Unified Cloud Deployment Script for ETH Watchtower
# Supports: Azure, GCP, AWS

set -e

# --- Default Variables ---
RESOURCE_PREFIX="eth-watch"
LOCATION_AZURE="eastus"
LOCATION_GCP="us-central1"
REGION_AWS="us-east-1"

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
    echo "  --remove           Nuke the deployment and associated resources"
    echo "  --verify           Verify the deployment and storage output"
    echo "  --help             Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 --provider azure --location westeurope"
    echo "  $0 --provider gcp --prefix my-watcher"
    echo "  $0 --provider azure --prefix my-watcher --verify"
    echo "  $0 --provider azure --prefix my-watcher --remove"
    exit 1
}

# --- Helper: Print endpoint summary ---
print_endpoints() {
    local BASE_URL="$1"
    local AUTH_USER="${2:-ethwatchtower}"
    local AUTH_PASS="${3:-ethwatchtower}"
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║          🚀  ETH Watchtower  —  Deployment Ready          ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo ""
    echo "  📡  Events (NDJSON stream, public):"
    echo "       ${BASE_URL}/events"
    echo ""
    echo "  📊  Metrics (Prometheus, public):"
    echo "       ${BASE_URL}/metrics"
    echo ""
    echo "  🗂️   Data files (Basic Auth required):"
    echo "       ${BASE_URL}/data/"
    echo "       User: ${AUTH_USER}   Pass: ${AUTH_PASS}"
    echo ""
    echo "  🔗  Quick-stream commands:"
    echo "       curl ${BASE_URL}/events"
    echo "       watch -n5 'curl -s ${BASE_URL}/events | tail -5'"
    echo ""
}

# --- Azure Deployment ---
deploy_azure() {
    local PREFIX=$1
    local LOC=${2:-$LOCATION_AZURE}
    local RG="${PREFIX}-rg"
    # ACR name: must be alphanumeric, 5-50 chars, globally unique (using a shorter hash or stable prefix)
    local ACR_BASE=$(echo "${PREFIX}" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')
    local ACR="${ACR_BASE:0:40}reg"
    # Storage name: 3-24 chars, numbers and lowercase only
    local STORAGE="${ACR_BASE:0:19}store"
    local SHARE="watchtower-data"
    local ENV="${PREFIX}-env"
    local APP="${PREFIX}-app"

    echo "🚀 Starting Azure Deployment..."
    echo "Resource Group: $RG"
    echo "Location: $LOC"

    if ! az group show --name "$RG" &>/dev/null; then
        echo "Creating Resource Group..."
        az group create --name "$RG" --location "$LOC"
    fi

    if ! az acr show --name "$ACR" --resource-group "$RG" &>/dev/null; then
        echo "Creating Container Registry..."
        az acr create --resource-group "$RG" --name "$ACR" --sku Basic
    fi
    
    ACR_LOGIN_SERVER=$(az acr show --resource-group "$RG" --name "$ACR" --query loginServer --output tsv)
    az acr login --resource-group "$RG" --name "$ACR"

    echo "📦 Building and Pushing Image..."
    docker build -t "$ACR_LOGIN_SERVER/eth-watchtower:latest" .
    docker push "$ACR_LOGIN_SERVER/eth-watchtower:latest"

    if ! az storage account show --name "$STORAGE" --resource-group "$RG" &>/dev/null; then
        echo "Creating Storage Account..."
        az storage account create --name "$STORAGE" --resource-group "$RG" --location "$LOC" --sku Standard_LRS --min-tls-version TLS1_2
    fi

    STORAGE_KEY=$(az storage account keys list --resource-group "$RG" --account-name "$STORAGE" --query "[0].value" --output tsv)
    
    if ! az storage share show --name "$SHARE" --account-name "$STORAGE" --account-key "$STORAGE_KEY" &>/dev/null; then
        echo "Creating File Share..."
        az storage share create --name "$SHARE" --account-name "$STORAGE" --account-key "$STORAGE_KEY"
    fi

    if ! az containerapp env show --name "$ENV" --resource-group "$RG" &>/dev/null; then
        echo "Creating Container App Environment..."
        az containerapp env create --name "$ENV" --resource-group "$RG" --location "$LOC"
    fi

    echo "Configuring Environment Storage..."
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

    local DEPLOY_TS=$(date +%s)

    echo "🏗️  Deploying Container App..."
    if az containerapp show --name "$APP" --resource-group "$RG" &>/dev/null; then
        echo "App exists — updating with new revision..."
        az containerapp update \
            --name "$APP" \
            --resource-group "$RG" \
            --image "$ACR_LOGIN_SERVER/eth-watchtower:latest" \
            --revision-suffix "r${DEPLOY_TS}"
    else
        echo "Creating new app..."
        az containerapp create \
            --name "$APP" \
            --resource-group "$RG" \
            --yaml aca-deploy.yaml
    fi

    rm -f aca-deploy.yaml
    echo "✅ Azure Deployment Complete!"
    FQDN=$(az containerapp show --name "$APP" --resource-group "$RG" --query properties.configuration.ingress.fqdn --output tsv)
    IFS=':' read -r AUTH_USER AUTH_PASS <<<"ethwatchtower:ethwatchtower"
    print_endpoints "https://${FQDN}" "${AUTH_USER}" "${AUTH_PASS}"
}

remove_azure() {
    local PREFIX=$1
    local RG="${PREFIX}-rg"
    echo "🗑️  Nuking Azure Resource Group: $RG ..."
    if az group show --name "$RG" &>/dev/null; then
        az group delete --name "$RG" --yes --no-wait
        echo "Cleanup initiated in background."
    else
        echo "Resource Group $RG not found."
    fi
}

verify_azure() {
    local PREFIX=$1
    local RG="${PREFIX}-rg"
    local ACR_BASE=$(echo "${PREFIX}" | tr -cd '[:alnum:]' | tr '[:upper:]' '[:lower:]')
    local STORAGE="${ACR_BASE:0:19}store"
    local SHARE="watchtower-data"
    local APP="${PREFIX}-app"

    echo "🔍 Verifying Azure Deployment..."
    
    echo ""
    echo "--- Revision Status ---"
    az containerapp revision list --name "$APP" --resource-group "$RG" --output table

    echo ""
    echo "--- Storage Output (Files in Share) ---"
    STORAGE_KEY=$(az storage account keys list --resource-group "$RG" --account-name "$STORAGE" --query "[0].value" --output tsv)
    az storage file list --share-name "$SHARE" --account-name "$STORAGE" --account-key "$STORAGE_KEY" \
        --query "[].{Name:name, Size:properties.contentLength, LastModified:properties.lastModified}" --output table

    echo ""
    echo "--- Recent Application Logs ---"
    az containerapp logs show --name "$APP" --resource-group "$RG" --follow false --tail 20 2>/dev/null || echo "(no logs yet)"

    URL=$(az containerapp show --name "$APP" --resource-group "$RG" --query properties.configuration.ingress.fqdn --output tsv)
    echo ""
    echo "--- Health Check: https://$URL ---"
    curl -s -f -I "https://$URL/metrics" >/dev/null && echo "✅ /metrics endpoint is UP" || echo "❌ /metrics endpoint is DOWN"
    curl -s -f -u "ethwatchtower:ethwatchtower" -I "https://$URL/data/" >/dev/null && echo "✅ /data/ endpoint (Auth) is UP" || echo "❌ /data/ endpoint (Auth) is DOWN"
}

# --- GCP Deployment ---
deploy_gcp() {
    local PREFIX=$1
    local LOC=${2:-$LOCATION_GCP}
    local PROJECT_ID=$(gcloud config get-value project)
    local REPO=$(echo "${PREFIX}-repo" | tr '[:upper:]' '[:lower:]')
    local BUCKET="${PROJECT_ID}-${PREFIX}-data"
    local SERVICE="${PREFIX}-service"
    local SA="${PREFIX}-sa"

    echo "🚀 Starting GCP Deployment..."
    echo "Project: $PROJECT_ID"
    echo "Location: $LOC"

    gcloud services enable artifactregistry.googleapis.com run.googleapis.com storage.googleapis.com

    if ! gcloud artifacts repositories describe "$REPO" --location="$LOC" &>/dev/null; then
        echo "Creating Artifact Registry..."
        gcloud artifacts repositories create "$REPO" \
            --repository-format=docker \
            --location="$LOC" \
            --description="Docker repository for ETH Watchtower"
    fi

    IMAGE_TAG="$LOC-docker.pkg.dev/$PROJECT_ID/$REPO/eth-watchtower:latest"
    
    echo "📦 Building and Pushing Image (via Cloud Build)..."
    gcloud builds submit --tag "$IMAGE_TAG" .

    if ! gsutil ls -b "gs://$BUCKET" &>/dev/null; then
        echo "Creating Cloud Storage Bucket..."
        gsutil mb -l "$LOC" "gs://$BUCKET"
    fi

    if ! gcloud iam service-accounts describe "$SA@$PROJECT_ID.iam.gserviceaccount.com" &>/dev/null; then
        echo "Creating Service Account..."
        gcloud iam service-accounts create "$SA" --display-name="Service Account for ETH Watchtower"
    fi

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
    SVC_URL=$(gcloud run services describe "$SERVICE" --region "$LOC" --format='value(status.url)')
    print_endpoints "${SVC_URL}" "ethwatchtower" "ethwatchtower"
}

remove_gcp() {
    local PREFIX=$1
    local LOC=${2:-$LOCATION_GCP}
    local PROJECT_ID=$(gcloud config get-value project)
    local SERVICE="${PREFIX}-service"
    local BUCKET="${PROJECT_ID}-${PREFIX}-data"
    local REPO=$(echo "${PREFIX}-repo" | tr '[:upper:]' '[:lower:]')

    echo "🗑️  Nuking GCP Service: $SERVICE ..."
    gcloud run services delete "$SERVICE" --region "$LOC" --quiet || true
    
    echo "🗑️  Deleting Bucket: gs://$BUCKET ..."
    gsutil rm -r "gs://$BUCKET" || true
    
    echo "🗑️  Deleting Repository: $REPO ..."
    gcloud artifacts repositories delete "$REPO" --location="$LOC" --quiet || true
}

verify_gcp() {
    local PREFIX=$1
    local LOC=${2:-$LOCATION_GCP}
    local PROJECT_ID=$(gcloud config get-value project)
    local SERVICE="${PREFIX}-service"
    local BUCKET="${PROJECT_ID}-${PREFIX}-data"

    echo "🔍 Verifying GCP Deployment..."
    
    echo "--- Cloud Run Status ---"
    gcloud run services describe "$SERVICE" --region "$LOC" --format="table(metadata.name, status.conditions[0].status, status.url)"
    
    echo "--- Storage Output ---"
    gsutil ls -lh "gs://$BUCKET"

    URL=$(gcloud run services describe "$SERVICE" --region "$LOC" --format='value(status.url)')
    echo "--- Health Check (Integrated Web Server) ---"
    curl -s -f -I "$URL/metrics" >/dev/null && echo "✅ Metrics endpoint is UP" || echo "❌ Metrics endpoint is DOWN"
    curl -s -f -u "ethwatchtower:ethwatchtower" -I "$URL/data/" >/dev/null && echo "✅ Data endpoint (Auth) is UP" || echo "❌ Data endpoint (Auth) is DOWN"
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

    if ! aws ecr describe-repositories --repository-names "$REPO" --region "$LOC" &>/dev/null; then
        echo "Creating ECR Repository..."
        aws ecr create-repository --repository-name "$REPO" --region "$LOC"
    fi

    IMAGE_TAG="$ACCOUNT_ID.dkr.ecr.$LOC.amazonaws.com/$REPO:latest"
    
    aws ecr get-login-password --region "$LOC" | docker login --username AWS --password-stdin "$ACCOUNT_ID.dkr.ecr.$LOC.amazonaws.com"
    docker build -t "$REPO" .
    docker tag "$REPO:latest" "$IMAGE_TAG"
    docker push "$IMAGE_TAG"

    FILE_SYSTEM_ID=$(aws efs describe-file-systems --creation-token "${PREFIX}-efs" --region "$LOC" --query "FileSystems[0].FileSystemId" --output tsv)
    if [ -z "$FILE_SYSTEM_ID" ]; then
        echo "Creating EFS File System..."
        FILE_SYSTEM_ID=$(aws efs create-file-system --creation-token "${PREFIX}-efs" --region "$LOC" --query FileSystemId --output tsv)
        
        echo "Waiting for EFS to be available..."
        while [[ $(aws efs describe-file-systems --file-system-id "$FILE_SYSTEM_ID" --region "$LOC" --query "FileSystems[0].LifeCycleState" --output tsv) != "available" ]]; do
            sleep 5
        done
        aws efs create-mount-target --file-system-id "$FILE_SYSTEM_ID" --subnet-id "$SUBNET_ID" --security-groups "$SG_ID" --region "$LOC"
    fi

    if ! aws ecs describe-clusters --clusters "$CLUSTER" --region "$LOC" --query "clusters[0].status" --output tsv | grep -q "ACTIVE"; then
        echo "Creating ECS Cluster..."
        aws ecs create-cluster --cluster-name "$CLUSTER" --region "$LOC"
    fi

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

    if ! aws ecs describe-services --cluster "$CLUSTER" --services "${PREFIX}-service" --region "$LOC" --query "services[0].status" --output tsv | grep -q "ACTIVE"; then
        echo "Creating ECS Service..."
        aws ecs create-service \
            --cluster "$CLUSTER" \
            --service-name "${PREFIX}-service" \
            --task-definition "$TASK_FAMILY" \
            --desired-count 1 \
            --launch-type FARGATE \
            --network-configuration "awsvpcConfiguration={subnets=[$SUBNET_ID],assignPublicIp=ENABLED,securityGroups=[$SG_ID]}" \
            --region "$LOC"
    else
        echo "Updating ECS Service..."
        aws ecs update-service \
            --cluster "$CLUSTER" \
            --service "${PREFIX}-service" \
            --task-definition "$TASK_FAMILY" \
            --force-new-deployment \
            --region "$LOC"
    fi

    echo "✅ AWS Deployment Complete!"
    echo "  Waiting up to 60s for task to be RUNNING..."
    for i in $(seq 1 12); do
        TASK_ARN=$(aws ecs list-tasks --cluster "$CLUSTER" --service-name "${PREFIX}-service" --region "$LOC" --query "taskArns[0]" --output tsv 2>/dev/null)
        TASK_STATUS=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$LOC" --query "tasks[0].lastStatus" --output tsv 2>/dev/null)
        [ "$TASK_STATUS" = "RUNNING" ] && break
        sleep 5
    done
    # Resolve the public IP from the ENI
    ENI_ID=$(aws ecs describe-tasks --cluster "$CLUSTER" --tasks "$TASK_ARN" --region "$LOC" \
        --query "tasks[0].attachments[0].details[?name=='networkInterfaceId'].value" --output tsv 2>/dev/null)
    PUBLIC_IP=$(aws ec2 describe-network-interfaces --network-interface-ids "$ENI_ID" --region "$LOC" \
        --query "NetworkInterfaces[0].Association.PublicIp" --output tsv 2>/dev/null)
    if [ -n "$PUBLIC_IP" ]; then
        print_endpoints "http://${PUBLIC_IP}:2112" "ethwatchtower" "ethwatchtower"
    else
        echo ""
        echo "  ⚠️  Could not resolve public IP yet. Once the task is RUNNING, use:"
        echo "     aws ecs describe-tasks --cluster ${CLUSTER} --tasks \$TASK_ARN --region ${LOC}"
        echo "     Then look up the ENI's public IP in EC2 → Network Interfaces."
        echo ""
    fi
}

remove_aws() {
    local PREFIX=$1
    local LOC=${2:-$REGION_AWS}
    local REPO="${PREFIX}-repo"
    local CLUSTER="${PREFIX}-cluster"
    local SERVICE="${PREFIX}-service"

    echo "🗑️  Nuking AWS Service: $SERVICE ..."
    aws ecs update-service --cluster "$CLUSTER" --service "$SERVICE" --desired-count 0 --region "$LOC" || true
    aws ecs delete-service --cluster "$CLUSTER" --service "$SERVICE" --force --region "$LOC" || true
    
    echo "🗑️  Deleting Cluster: $CLUSTER ..."
    aws ecs delete-cluster --cluster "$CLUSTER" --region "$LOC" || true
    
    echo "🗑️  Deleting Repository: $REPO ..."
    aws ecr delete-repository --repository-name "$REPO" --force --region "$LOC" || true
    
    FILE_SYSTEM_ID=$(aws efs describe-file-systems --creation-token "${PREFIX}-efs" --region "$LOC" --query "FileSystems[0].FileSystemId" --output tsv)
    if [ -n "$FILE_SYSTEM_ID" ]; then
        echo "🗑️  Deleting EFS: $FILE_SYSTEM_ID ..."
        aws efs delete-file-system --file-system-id "$FILE_SYSTEM_ID" --region "$LOC" || true
    fi
}

verify_aws() {
    local PREFIX=$1
    local LOC=${2:-$REGION_AWS}
    local CLUSTER="${PREFIX}-cluster"
    local SERVICE="${PREFIX}-service"
    local TASK_FAMILY="${PREFIX}-task"

    echo "🔍 Verifying AWS Deployment..."
    
    echo "--- ECS Service Status ---"
    aws ecs describe-services --cluster "$CLUSTER" --services "$SERVICE" --region "$LOC" --query "services[].{Name:serviceName, Status:status, Running:runningCount, Desired:desiredCount}" --output table
    
    echo "--- CloudWatch Log Stream (Last 5 lines) ---"
    LOG_STREAM=$(aws logs describe-log-streams --log-group-name "/ecs/$TASK_FAMILY" --region "$LOC" --order-by LastEventTime --descending --limit 1 --query "logStreams[0].logStreamName" --output tsv)
    if [ -n "$LOG_STREAM" ]; then
        aws logs get-log-events --log-group-name "/ecs/$TASK_FAMILY" --log-stream-name "$LOG_STREAM" --region "$LOC" --limit 5 --query "events[].message" --output table
    else
        echo "No logs found."
    fi

    # Note: Accessing Fargate public IP/DNS requires extracting it from the ENI.
    # Showing how to check logs is usually enough for "outputting events" verification in ECS/EFS.
}

# --- Main Logic ---

PROVIDER=""
PREFIX=$RESOURCE_PREFIX
LOCATION=""
REMOVE_FLAG=false
VERIFY_FLAG=false

while [[ "$#" -gt 0 ]]; do
    case $1 in
        --provider) PROVIDER="$2"; shift ;;
        --prefix) PREFIX="$2"; shift ;;
        --location|--region) LOCATION="$2"; shift ;;
        --remove) REMOVE_FLAG=true ;;
        --verify) VERIFY_FLAG=true ;;
        --help) usage ;;
        *) echo "Unknown parameter: $1"; usage ;;
    esac
    shift
done

if [[ -z "$PROVIDER" ]]; then
    echo "Error: --provider is required."
    usage
fi

if [ "$REMOVE_FLAG" = true ]; then
    case $PROVIDER in
        azure) remove_azure "$PREFIX" ;;
        gcp)   remove_gcp   "$PREFIX" "$LOCATION" ;;
        aws)   remove_aws   "$PREFIX" "$LOCATION" ;;
    esac
    exit 0
fi

if [ "$VERIFY_FLAG" = true ]; then
    case $PROVIDER in
        azure) verify_azure "$PREFIX" ;;
        gcp)   verify_gcp   "$PREFIX" "$LOCATION" ;;
        aws)   verify_aws   "$PREFIX" "$LOCATION" ;;
    esac
    exit 0
fi

case $PROVIDER in
    azure) deploy_azure "$PREFIX" "$LOCATION" ;;
    gcp)   deploy_gcp   "$PREFIX" "$LOCATION" ;;
    aws)   deploy_aws   "$PREFIX" "$LOCATION" ;;
    *)     echo "Error: Invalid provider '$PROVIDER'. Use azure, gcp, or aws."; exit 1 ;;
esac
