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

# Check if secrets exist in cluster (don't require local secrets.yaml for CI/CD)
echo "Checking if secrets exist in cluster..."
if kubectl get secret photography-secrets -n hallphotography >/dev/null 2>&1; then
    echo "✅ Secrets already exist in cluster, skipping secrets deployment"
    SKIP_SECRETS=true
else
    echo "⚠️  Secrets not found in cluster"
    if [ -f "k8s/shared/secrets.yaml" ]; then
        echo "✅ Found secrets.yaml locally, will apply it"
        SKIP_SECRETS=false
    else
        echo "ERROR: No secrets found in cluster AND no local secrets.yaml file!"
        echo ""
        echo "For CI/CD deployments, secrets should be pre-configured in the cluster."
        echo "For local development, create secrets.yaml from the template:"
        echo "  cp k8s/shared/secrets-template.yaml k8s/shared/secrets.yaml"
        echo "  # Edit k8s/shared/secrets.yaml with your actual values"
        echo "  kubectl apply -f k8s/shared/secrets.yaml"
        echo ""
        exit 1
    fi
fi

echo "Deploying Photography app..."
# Apply secrets only if we determined we should
if [ "$SKIP_SECRETS" = "false" ]; then
    echo "Applying secrets..."
    kubectl apply -f k8s/shared/secrets.yaml
else
    echo "Skipping secrets deployment (already exist in cluster)"
fi

# Deploy the photography app
kubectl apply -k k8s/photography/

echo ""
echo "Forcing deployment rollout to ensure new image is pulled..."
# Force restart to pull the latest image with updated code
kubectl rollout restart deployment/photography -n hallphotography

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
    if sudo -n systemctl restart cloudflared 2>/dev/null; then
        echo "✅ Cloudflared service restarted"
    else
        echo "⚠️  Could not restart cloudflared automatically (sudo requires password)"
        echo ""
        echo "To fix this for future deployments, run the setup script:"
        echo "  ./k8s/setup-passwordless-sudo.sh"
        echo ""
        echo "Or manually restart cloudflared now:"
        echo "  sudo systemctl restart cloudflared"
        echo ""
        echo "The photography app is deployed but Cloudflare tunnel may need manual restart."
    fi
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
