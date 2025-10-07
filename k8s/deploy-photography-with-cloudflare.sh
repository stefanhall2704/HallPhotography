#!/bin/bash
set -e

echo "========================================="
echo "Photography App Deployment with Cloudflare Update"
echo "========================================="
echo ""

# Configuration
PHOTOGRAPHY_NODEPORT=31055
CONTROL_PLANE_IP="192.168.1.102"
CLOUDFLARE_CONFIG="/etc/cloudflared/config.yml"

# Check if secrets file exists locally, or if secrets already exist in cluster
if [ ! -f "shared/secrets.yaml" ]; then
    echo "secrets.yaml not found locally, checking if secrets exist in cluster..."
    if kubectl get secret photography-secrets -n hallphotography >/dev/null 2>&1; then
        echo "✅ Secrets already exist in cluster, skipping secrets deployment"
    else
        echo "ERROR: secrets.yaml not found locally AND secrets don't exist in cluster!"
        echo ""
        echo "Please create secrets.yaml from the template:"
        echo "  cp shared/secrets-template.yaml shared/secrets.yaml"
        echo "  # Edit shared/secrets.yaml with your actual values"
        echo "  kubectl apply -f shared/secrets.yaml"
        echo ""
        exit 1
    fi
else
    echo "✅ Found secrets.yaml locally"
fi

echo "Deploying Photography app..."
# Apply secrets if they exist locally
if [ -f "shared/secrets.yaml" ]; then
    echo "Applying secrets..."
    kubectl apply -f shared/secrets.yaml
fi

# Deploy the photography app
kubectl apply -k photography/

echo ""
echo "Waiting for Photography app to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/photography -n hallphotography

echo ""
echo "Verifying service has correct NodePort..."
ACTUAL_NODEPORT=$(kubectl get svc photography -n hallphotography -o jsonpath='{.spec.ports[0].nodePort}')
if [ "$ACTUAL_NODEPORT" != "$PHOTOGRAPHY_NODEPORT" ]; then
    echo "ERROR: Service NodePort is $ACTUAL_NODEPORT, expected $PHOTOGRAPHY_NODEPORT"
    echo "The photography-service.yaml may not have the fixed nodePort configured correctly."
    exit 1
fi

echo "✅ Service NodePort is correct: $PHOTOGRAPHY_NODEPORT"

echo ""
echo "Updating Cloudflare tunnel configuration..."
if [ -f "$CLOUDFLARE_CONFIG" ]; then
    # Backup current config
    sudo cp "$CLOUDFLARE_CONFIG" "$CLOUDFLARE_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Update the NodePort in the config
    sudo sed -i "s|https://$CONTROL_PLANE_IP:[0-9]*|https://$CONTROL_PLANE_IP:$PHOTOGRAPHY_NODEPORT|g" "$CLOUDFLARE_CONFIG"
    
    echo "✅ Cloudflare config updated to use NodePort $PHOTOGRAPHY_NODEPORT"
    
    # Restart cloudflared
    echo "Restarting cloudflared service..."
    sudo systemctl restart cloudflared
    
    echo "✅ Cloudflared service restarted"
else
    echo "WARNING: Cloudflare config not found at $CLOUDFLARE_CONFIG"
    echo "Please manually update your Cloudflare tunnel to use:"
    echo "  https://$CONTROL_PLANE_IP:$PHOTOGRAPHY_NODEPORT"
fi

echo ""
echo "========================================="
echo "Photography Deployment Complete!"
echo "========================================="
echo ""
echo "Service Details:"
echo "  NodePort: $PHOTOGRAPHY_NODEPORT"
echo "  Control Plane IP: $CONTROL_PLANE_IP"
echo "  External URL: https://$CONTROL_PLANE_IP:$PHOTOGRAPHY_NODEPORT"
echo ""
echo "Check status with:"
echo "  kubectl get pods -n hallphotography -l app=photography"
echo "  kubectl get svc -n hallphotography -l app=photography"
echo ""
