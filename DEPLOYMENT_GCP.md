# GCP Deployment Guide: ETH Watchtower

This guide details how to deploy ETH Watchtower to **Google Cloud Run** with persistent output to **Google Cloud Storage (GCS)** using the `gcloud` CLI.

## Prerequisites

- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and initialized (`gcloud init`).
- A GCP project with billing enabled.
- Docker installed locally (if not using Cloud Build).

## Deployment Steps

### 1. Set Environment Variables

```bash
PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"
REPO_NAME="eth-watchtower"
BUCKET_NAME="eth-watchtower-data-$(date +%s)"
SERVICE_NAME="eth-watchtower"
```

### 2. Enable Required APIs

```bash
gcloud services enable \
    artifactregistry.googleapis.com \
    run.googleapis.com \
    storage.googleapis.com
```

### 3. Setup Artifact Registry

```bash
# Create repository
gcloud artifacts repositories create $REPO_NAME \
    --repository-format=docker \
    --location=$REGION \
    --description="Docker repository for ETH Watchtower"

# Configure docker auth
gcloud auth configure-docker $REGION-docker.pkg.dev
```

### 4. Build and Push Image

You can use Google Cloud Build to build and push in one step without local Docker:

```bash
IMAGE_TAG="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO_NAME/eth-watchtower:latest"

gcloud builds submit --tag $IMAGE_TAG .
```

### 5. Setup Cloud Storage (Object Storage)

```bash
# Create the bucket
gsutil mb -l $REGION gs://$BUCKET_NAME
```

### 6. Create a Service Account for the Container

```bash
SA_NAME="eth-watchtower-sa"

gcloud iam service-accounts create $SA_NAME \
    --display-name="Service Account for ETH Watchtower"

# Grant permission to write to the bucket
gcloud storage buckets add-iam-policy-binding gs://$BUCKET_NAME \
    --member="serviceAccount:$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectAdmin"
```

### 7. Deploy to Cloud Run

We utilize Cloud Run's ability to mount GCS buckets as volumes.

```bash
gcloud run deploy $SERVICE_NAME \
    --image $IMAGE_TAG \
    --region $REGION \
    --service-account "$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
    --add-volume=name=watchtower-data,type=cloud-storage,bucket=$BUCKET_NAME \
    --add-volume-mount=volume=watchtower-data,mount-path=/app/data \
    --args="-config","/app/config.json" \
    --port=2112 \
    --allow-unauthenticated \
    --min-instances=1
```

## Accessing Logs and Data

Persistent data and logs are available via either the cloud portal or the integrated web server.

### 1. Web Access (Secure)
Access the logs in your browser using the Service URL at the `/data/` endpoint:
- **URL**: `https://<your-cloud-run-url>/data/`
- **Username**: `ethwatchtower`
- **Password**: `ethwatchtower`

### 2. GCS Browser
You can view your files directly in the Google Cloud Console under Storage or use the CLI:

```bash
# List files
gsutil ls gs://$BUCKET_NAME

# Download a file
gsutil cp gs://$BUCKET_NAME/eth-watchtower.jsonl .
```

## Monitoring

The service endpoint provides Prometheus metrics on `/metrics`.

```bash
# Get the service URL
gcloud run services describe $SERVICE_NAME --region $REGION --format='value(status.url)'
```
