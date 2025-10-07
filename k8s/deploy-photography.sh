#!/bin/bash
set -e

echo "========================================="
echo "Photography App Deployment"
echo "========================================="
echo ""

# Check if secrets file exists
if [ ! -f "shared/secrets.yaml" ]; then
    echo "ERROR: secrets.yaml not found!"
    echo ""
    echo "Please create secrets.yaml from the template:"
    echo "  cp shared/secrets-template.yaml shared/secrets.yaml"
    echo "  # Edit shared/secrets.yaml with your actual values"
    echo "  kubectl apply -f shared/secrets.yaml"
    echo ""
    exit 1
fi

echo "Deploying Photography app..."
kubectl apply -k photography/

echo ""
echo "Waiting for Photography app to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/photography -n hallphotography

echo ""
echo "========================================="
echo "Photography Deployment Complete!"
echo "========================================="
echo ""
echo "Check status with:"
echo "  kubectl get pods -n hallphotography -l app=photography"
echo "  kubectl get svc -n hallphotography -l app=photography"
echo ""
