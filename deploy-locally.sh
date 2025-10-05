#!/bin/bash

# Photography App Local Deployment Script
# This script updates the deployment with the latest image and deploys to your local cluster

set -e

# Configuration
REGISTRY="docker.io"
IMAGE_NAME="stefanmhall/photography"
NAMESPACE="hallphotography"
DEPLOYMENT_NAME="photography"

# Get the latest commit SHA
LATEST_SHA=$(git rev-parse HEAD)
IMAGE_TAG="${LATEST_SHA}"

echo "🚀 Deploying Photography App to local Kubernetes cluster..."
echo "Image: ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed or not in PATH"
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    echo "❌ Cannot connect to Kubernetes cluster"
    echo "Make sure your cluster is running and kubectl is configured"
    exit 1
fi

# Create namespace if it doesn't exist
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# Update image in deployment
echo "📝 Updating deployment with new image..."
sed -i "s|image: .*|image: ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}|g" k8s/photography-deployment.yaml

# Apply manifests
echo "🔧 Applying Kubernetes manifests..."
kubectl apply -f k8s/photography-deployment.yaml -n ${NAMESPACE}
kubectl apply -f k8s/photography-service.yaml -n ${NAMESPACE}

# Wait for rollout
echo "⏳ Waiting for deployment to complete..."
kubectl rollout status deployment/${DEPLOYMENT_NAME} -n ${NAMESPACE} --timeout=300s

# Verify deployment
echo "✅ Photography app deployed successfully!"
echo "Image: ${REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
echo "Namespace: ${NAMESPACE}"
echo ""
echo "📊 Deployment status:"
kubectl get pods -n ${NAMESPACE} -l app=photography
echo ""
echo "🌐 Service status:"
kubectl get svc -n ${NAMESPACE} -l app=photography
