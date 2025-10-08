# Hall Photography Kubernetes Deployment

This directory contains the Kubernetes configurations for the Hall Photography application.

## Directory Structure

```
k8s/
├── shared/                    # Shared components
│   ├── namespace.yaml        # Namespace definition
│   ├── dns-config.yaml       # DNS configuration
│   ├── secrets-template.yaml # Secrets template (copy to secrets.yaml)
│   └── secrets.yaml          # Actual secrets (not in git)
├── photography/              # Photography application
│   ├── photography-pvc.yaml  # Persistent volume claims
│   ├── photography-deployment.yaml
│   ├── photography-service.yaml
│   ├── photography-ingress.yaml
│   └── kustomization.yaml
├── kustomization.yaml        # Main kustomization file
├── deploy-photography.sh    # Deploy photography app
└── README.md                # This file
```

## Quick Start

### 1. Setup Secrets

**For Local Development:**
```bash
# Copy the template and fill in your values
cp shared/secrets-template.yaml shared/secrets.yaml
# Edit shared/secrets.yaml with your actual values (TLS certs, DB creds, etc.)
kubectl apply -f shared/secrets.yaml
```

**For CI/CD Deployments:**
Secrets should be pre-configured in the cluster. The deployment script will skip secrets if they already exist.

### 2. Deploy Photography App

```bash
# Deploy photography app (basic)
./deploy-photography.sh

# Deploy photography app with Cloudflare tunnel update (recommended)
./deploy-photography-with-cloudflare.sh
```

### 3. Manual Deployment

```bash
# Deploy shared components
kubectl apply -f shared/namespace.yaml
kubectl apply -f shared/dns-config.yaml
kubectl apply -f shared/secrets.yaml

# Deploy Photography app
kubectl apply -k photography/
```

## Components

### Photography App
- **Image**: `stefanmhall/photography:latest`
- **Port**: 8080 (HTTPS)
- **NodePort**: 31055 (fixed)
- **Domain**: `photography.stefan-sre.com`
- **Features**: Google OAuth, file uploads/downloads, PostgreSQL database

### Dependencies
- **PostgreSQL**: External database (deployed separately)
- **TLS Certificates**: Required for HTTPS and Google OAuth
- **Google OAuth**: Configured for authentication

## CI/CD Pipeline

The GitHub Actions workflow (`deploy.yml`) handles:

1. **Build**: Builds Docker image and pushes to Docker Hub
2. **Deploy**: SSH deployment to your Kubernetes cluster
3. **Verify**: Confirms successful deployment

### Required GitHub Secrets

**Deployment Secrets:**
- `DOCKER_USERNAME`: Your Docker Hub username
- `DOCKER_PASSWORD`: Your Docker Hub password/token
- `SSH_HOST`: Your server IP/hostname
- `SSH_USERNAME`: SSH username
- `SSH_PRIVATE_KEY`: SSH private key

**Application Secrets:**
- `SESSION_SECRET`: Your session secret key
- `GOOGLE_CLIENT_ID`: Google OAuth client ID
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `GOOGLE_CALLBACK_URL`: Google OAuth callback URL
- `DB_USER`: Database username
- `DB_PASSWORD`: Database password
- `DB_NAME`: Database name
- `SERVER_CERT`: TLS certificate (full certificate including BEGIN/END lines)
- `SERVER_KEY`: TLS private key (full key including BEGIN/END lines)
- `CALENDAR_TOKEN_JSON`: Google Calendar token JSON (optional)
- `TOKEN_JSON`: Additional token JSON (optional)

**To add secrets:**
1. Go to your GitHub repository
2. Settings → Secrets and variables → Actions
3. Click "New repository secret"
4. Add each secret with the exact name listed above

## Troubleshooting

### Check Status
```bash
kubectl get pods -n hallphotography
kubectl get svc -n hallphotography
kubectl get ingress -n hallphotography
```

### View Logs
```bash
kubectl logs -f deployment/photography -n hallphotography
```

### Restart Services
```bash
kubectl rollout restart deployment/photography -n hallphotography
```

## Network Configuration

- **Photography**: Fixed NodePort 31055 on control plane (192.168.1.102)
- **Cloudflare Tunnel**: Automatically updated to use fixed NodePort 31055
- **External Access**: `photography.stefan-sre.com` → `https://192.168.1.102:31055`

## Preventing NodePort Drift

The photography service uses a **fixed NodePort (31055)** to prevent deployment issues. The enhanced deployment script (`deploy-photography-with-cloudflare.sh`) automatically:

1. ✅ Verifies the service has the correct NodePort
2. ✅ Updates Cloudflare tunnel configuration
3. ✅ Restarts cloudflared service
4. ✅ Provides deployment verification

This prevents the 502 errors caused by NodePort/IP mismatches.

## Security Notes

- All secrets are stored in Kubernetes secrets
- TLS certificates are mounted as secrets
- Google OAuth requires HTTPS (configured in ingress)
- Database credentials are stored securely
