# Azure Deployment Guide: ETH Watchtower

This guide provides step-by-step instructions to deploy ETH Watchtower to **Azure Container Apps (ACA)** with persistent output to **Azure Blob Storage (via Azure Files)**.

## Prerequisites

- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli) installed and logged in (`az login`).
- Docker installed locally (for building the image).

## Deployment Steps

### 1. Set Environment Variables

```bash
RESOURCE_GROUP="eth-watcher-rg"
LOCATION="eastus"
ACR_NAME="ethwatchreg"$(date +%s) # Must be globally unique
STORAGE_ACCOUNT="ethwatchstore"$(date +%s)
SHARE_NAME="watchtower-data"
ENVIRONMENT_NAME="eth-watcher-env"
CONTAINER_APP_NAME="eth-watcher-app"
```

### 2. Create Resource Group

```bash
az group create --name $RESOURCE_GROUP --location $LOCATION
```

### 3. Setup Azure Container Registry (ACR)

```bash
# Create ACR
az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic

# Login to ACR
az acr login --resource-group $RESOURCE_GROUP --name $ACR_NAME
```

### 4. Build and Push Image

```bash
# Get the login server address
ACR_LOGIN_SERVER=$(az acr show --resource-group $RESOURCE_GROUP --name $ACR_NAME --query loginServer --output tsv)

# Build the image locally
docker build -t $ACR_LOGIN_SERVER/eth-watchtower:latest .

# Push to ACR
docker push $ACR_LOGIN_SERVER/eth-watchtower:latest
```

### 5. Setup Persistent Storage (Azure Files)

We mount Azure Files to the container so that `.log` and `.jsonl` files are persisted in Azure Storage.

```bash
# Create Storage Account
az storage account create --name $STORAGE_ACCOUNT --resource-group $RESOURCE_GROUP --location $LOCATION --sku Standard_LRS

# Get Storage Account Connection String
STORAGE_KEY=$(az storage account keys list --resource-group $RESOURCE_GROUP --account-name $STORAGE_ACCOUNT --query "[0].value" --output tsv)

# Create File Share
az storage share create --name $SHARE_NAME --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY
```

### 6. Create Container Apps Environment

```bash
az containerapp env create --name $ENVIRONMENT_NAME --resource-group $RESOURCE_GROUP --location $LOCATION
```

### 7. Configure Storage in Container App Environment

```bash
az containerapp env storage set \
  --name $ENVIRONMENT_NAME \
  --resource-group $RESOURCE_GROUP \
  --storage-name $SHARE_NAME \
  --azure-file-account-name $STORAGE_ACCOUNT \
  --azure-file-account-key $STORAGE_KEY \
  --azure-file-share-name $SHARE_NAME \
  --access-mode ReadWrite
```

### 8. Deploy the Container App (using YAML)

Azure Container Apps require a YAML configuration for mounting volumes.

```bash
# Enable ACR Admin user (needed for credentials)
az acr update --name $ACR_NAME --resource-group $RESOURCE_GROUP --admin-enabled true

# Get ACR Credentials
ACR_USERNAME=$(az acr credential show --name $ACR_NAME --resource-group $RESOURCE_GROUP --query username -o tsv)
ACR_PASSWORD=$(az acr credential show --name $ACR_NAME --resource-group $RESOURCE_GROUP --query "passwords[0].value" -o tsv)

# Get Environment ID
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
ENVIRONMENT_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP/providers/Microsoft.App/managedEnvironments/$ENVIRONMENT_NAME"

# Create Deployment YAML
cat <<EOF > aca-deploy.yaml
name: $CONTAINER_APP_NAME
location: $LOCATION
type: Microsoft.App/containerApps
properties:
  managedEnvironmentId: $ENVIRONMENT_ID
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
        storageName: $SHARE_NAME
        storageType: AzureFile
EOF

# Deploy the App
az containerapp create \
  --resource-group $RESOURCE_GROUP \
  --yaml aca-deploy.yaml

# Clean up
rm aca-deploy.yaml
```

> **Note on config.json**: You can bake the `config.json` into the image, or mount it as a secret. If you want to customize output paths, ensure they point to `/app/data/`.

## Accessing Logs and Data

Persistent data and logs are available via either the cloud portal or the integrated web server.

### 1. Web Access (Secure)
Access the logs in your browser using the Container App's URL at the `/data/` endpoint:
- **URL**: `https://<your-app-fqdn>/data/`
- **Username**: `ethwatchtower`
- **Password**: `ethwatchtower`

### 2. Azure Portal
You can browse the `watchtower-data` file share in the Azure Portal under your Storage Account, or use the CLI:

```bash
# List files in the share
az storage file list --share-name $SHARE_NAME --account-name $STORAGE_ACCOUNT --account-key $STORAGE_KEY --output table
```

## Monitoring

Prometheus metrics are available at the Container App's URL (ingress endpoint) on `/metrics`.

```bash
# Get the URL
az containerapp show --name $CONTAINER_APP_NAME --resource-group $RESOURCE_GROUP --query properties.configuration.ingress.fqdn --output tsv
```
