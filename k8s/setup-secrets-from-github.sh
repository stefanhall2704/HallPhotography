#!/bin/bash
set -e

echo "========================================="
echo "Setting up secrets from GitHub secrets"
echo "========================================="
echo ""

# Function to create secret if it doesn't exist
create_secret_if_missing() {
    local secret_name=$1
    local namespace=$2
    shift 2
    local args=("$@")
    
    if ! kubectl get secret "$secret_name" -n "$namespace" >/dev/null 2>&1; then
        echo "Creating $secret_name secret..."
        kubectl create secret generic "$secret_name" -n "$namespace" "${args[@]}"
        echo "✅ $secret_name secret created"
    else
        echo "✅ $secret_name secret already exists"
    fi
}

# Create/update photography secrets (always update to ensure real values)
echo "Updating photography secrets with real values..."
kubectl delete secret photography-secrets -n hallphotography --ignore-not-found=true
kubectl create secret generic photography-secrets -n hallphotography \
    --from-literal=SESSION_SECRET="$SESSION_SECRET" \
    --from-literal=GOOGLE_CLIENT_ID="$GOOGLE_CLIENT_ID" \
    --from-literal=GOOGLE_CLIENT_SECRET="$GOOGLE_CLIENT_SECRET" \
    --from-literal=GOOGLE_CALLBACK_URL="$GOOGLE_CALLBACK_URL"
echo "✅ Photography secrets updated with real values"

# Create database secrets
create_secret_if_missing "db-secrets" "hallphotography" \
    --from-literal=DB_USER="$DB_USER" \
    --from-literal=DB_PASSWORD="$DB_PASSWORD" \
    --from-literal=DB_NAME="$DB_NAME"

# Create/update TLS certificates (always update to ensure real certs)
echo "Updating TLS certificates with real certificates..."
kubectl delete secret tls-certs -n hallphotography --ignore-not-found=true
kubectl create secret generic tls-certs -n hallphotography \
    --from-literal=server.crt="$SERVER_CERT" \
    --from-literal=server.key="$SERVER_KEY"
echo "✅ TLS certificates updated with real certificates"

# Create calendar secrets (with empty values for now)
create_secret_if_missing "calendar-secrets" "hallphotography" \
    --from-literal=calendar-token.json='{}' \
    --from-literal=token.json='{}'

echo ""
echo "========================================="
echo "Secrets setup complete!"
echo "========================================="
echo ""
