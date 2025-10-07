# Production Deployment Guide

This guide covers deploying the Hall's Photography application to a production Kubernetes cluster.

## What Changed for Production

### Database Migration (SQLite → PostgreSQL)

The application has been migrated from SQLite to PostgreSQL for production readiness:

- **Connection Pooling**: PostgreSQL driver with connection pooling (max 25 connections, 5 idle)
- **Singleton Pattern**: Database connection is initialized once and reused across requests
- **Database-Agnostic SQL**: All queries work with PostgreSQL, MySQL, and SQLite
- **Production Configuration**: Configurable via environment variables

### Key Improvements

1. **Singleton Database Connection**: The app no longer creates a new database connection on every request. Instead, it uses a singleton pattern that creates one connection pool at startup.

2. **Connection Pool Settings**:
   - Max Open Connections: 25
   - Max Idle Connections: 5
   - Connection Max Lifetime: 5 minutes
   - Connection Max Idle Time: 10 minutes

3. **Graceful Shutdown**: Database connections are properly closed when the application exits.

## Environment Variables

### Required Variables

```bash
# Session configuration
SESSION_SECRET=your-secure-random-string

# Google OAuth (if using)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_CALLBACK_URL=https://yourdomain.com/auth/google/callback

# Database configuration (PostgreSQL)
DB_HOST=postgres-service-name
DB_PORT=5432
DB_USER=hallphotography
DB_PASSWORD=your-secure-password
DB_NAME=hallphotography
DB_SSLMODE=require
```

### Notes

- In Kubernetes, `DB_HOST` should point to your PostgreSQL service name
- For production, set `DB_SSLMODE=require` for encrypted connections
- Use Kubernetes Secrets for sensitive values (passwords, secrets)

## Kubernetes Deployment Checklist

### 1. Database Setup

You have two options for PostgreSQL in Kubernetes:

#### Option A: Managed Database (Recommended for Production)
- Use a managed PostgreSQL service from your cloud provider:
  - **AWS**: RDS for PostgreSQL
  - **Google Cloud**: Cloud SQL for PostgreSQL
  - **Azure**: Azure Database for PostgreSQL
  - **DigitalOcean**: Managed Databases

Benefits:
- Automatic backups
- High availability
- Automated patching
- Better performance

#### Option B: PostgreSQL in Kubernetes
- Deploy PostgreSQL as a StatefulSet with persistent volumes
- Requires more management and monitoring
- Suitable for smaller deployments or development

### 2. Persistent Storage

The application needs persistent storage for:

```
/root/uploads/profile_pictures  - User profile pictures
/root/uploads/session_photos    - Session photos uploaded by photographer
/root/downloads                 - Downloaded photo archives
```

**Kubernetes Configuration**:
- Use PersistentVolumeClaims (PVC) for these directories
- Mount them to the appropriate paths in your deployment
- Consider using cloud storage (S3, GCS, Azure Blob) for better scalability

### 3. SSL/TLS Certificates

The application currently expects SSL certificates at:
```
/root/server.crt
/root/server.key
```

**For Kubernetes**, you have better options:

#### Recommended: Use Ingress with Cert-Manager
1. Remove TLS handling from the application
2. Update `main.go` to use HTTP instead of HTTPS:
   ```go
   http.ListenAndServe(":8080", loggedHandler)
   ```
3. Use a Kubernetes Ingress controller (NGINX, Traefik) with TLS termination
4. Use cert-manager for automatic certificate management with Let's Encrypt

#### Alternative: Keep Application TLS
- Store certificates in Kubernetes Secrets
- Mount secrets as volumes in your pod

### 4. Application Deployment

Your container image is ready for Kubernetes with:
- Health checks configured
- Graceful shutdown handling
- No local file dependencies (except uploads)

Key considerations:
- **Replicas**: Start with 2-3 replicas for high availability
- **Resources**: Set appropriate CPU/memory limits and requests
- **Probes**: Use the built-in health check endpoint

### 5. Configuration Management

**Use Kubernetes ConfigMaps and Secrets**:

```yaml
# ConfigMap for non-sensitive config
apiVersion: v1
kind: ConfigMap
metadata:
  name: hallphotography-config
data:
  DB_HOST: "postgres-service"
  DB_PORT: "5432"
  DB_NAME: "hallphotography"
  DB_SSLMODE: "require"

---
# Secret for sensitive data
apiVersion: v1
kind: Secret
metadata:
  name: hallphotography-secrets
type: Opaque
stringData:
  SESSION_SECRET: "your-secret-here"
  DB_USER: "hallphotography"
  DB_PASSWORD: "your-password-here"
  GOOGLE_CLIENT_ID: "your-client-id"
  GOOGLE_CLIENT_SECRET: "your-client-secret"
```

### 6. Database Migrations

The application automatically runs migrations on startup. For zero-downtime deployments:

1. **First Deployment**: Let the app run migrations automatically
2. **Subsequent Updates**: 
   - Test migrations in a staging environment first
   - Consider running migrations as a Kubernetes Job before deployment
   - Use GORM's migration features carefully with schema changes

### 7. Monitoring and Logging

Consider adding:

- **Logging**: Application logs to stdout (already done)
- **Metrics**: Add Prometheus metrics for monitoring
- **Tracing**: Consider adding distributed tracing (Jaeger, Zipkin)
- **Health Checks**: The Dockerfile includes a health check endpoint

## Docker Compose (Development/Testing)

For local testing or small deployments:

```bash
# Copy example.env to .env and configure
cp example.env .env
nano .env

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

The PostgreSQL data is stored in a Docker volume named `postgres-data`.

## Building the Container

```bash
# Build the image
docker build -t hallphotography:latest .

# Tag for your registry
docker tag hallphotography:latest your-registry.com/hallphotography:latest

# Push to registry
docker push your-registry.com/hallphotography:latest
```

## Security Considerations

1. **Environment Variables**: Never commit `.env` files with real credentials
2. **Database Password**: Use strong, randomly generated passwords
3. **Session Secret**: Generate a secure random string (32+ characters)
4. **SSL/TLS**: Always use encrypted connections in production
5. **Database SSL**: Set `DB_SSLMODE=require` for production
6. **Network Policies**: Restrict database access to only the application pods
7. **RBAC**: Use Kubernetes RBAC for access control

## Migrating from SQLite

If you have existing SQLite data:

1. **Export Data**: Use a migration tool or custom script to export SQLite data
2. **Import to PostgreSQL**: 
   ```bash
   # Example using pg_dump format
   pg_restore -h localhost -U hallphotography -d hallphotography backup.dump
   ```
3. **Verify Data**: Check that all tables and relationships are intact
4. **Test Application**: Run thorough tests before going live

## Performance Tuning

### Database Connection Pool

Adjust these values in `db/db.go` based on your load:

```go
sqlDB.SetMaxOpenConns(25)  // Increase for high traffic
sqlDB.SetMaxIdleConns(5)   // Keep low to reduce overhead
```

### PostgreSQL Configuration

For production PostgreSQL, tune these settings:
- `max_connections`: Should be > MaxOpenConns × number of app replicas
- `shared_buffers`: Set to 25% of available RAM
- `effective_cache_size`: Set to 50-75% of available RAM
- `work_mem`: Adjust based on query complexity

### Kubernetes Resource Limits

Start with:
```yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"
```

Adjust based on actual usage patterns.

## Troubleshooting

### Connection Issues

```bash
# Check if app can reach database
kubectl exec -it deployment/hallphotography -- /bin/sh
wget -O- http://localhost:8080/

# Check environment variables
kubectl exec -it deployment/hallphotography -- env | grep DB_
```

### Database Connection Errors

Common issues:
1. **Wrong DB_HOST**: Should be the Kubernetes service name
2. **Authentication Failed**: Check username/password in secrets
3. **SSL Mode**: Ensure PostgreSQL is configured for SSL if using `require`
4. **Connection Timeout**: Check network policies and service configuration

### Logs

```bash
# View application logs
kubectl logs -f deployment/hallphotography

# View database logs (if in K8s)
kubectl logs -f statefulset/postgres
```

## Next Steps

1. Create Kubernetes manifests (Deployment, Service, Ingress, etc.)
2. Set up CI/CD pipeline for automated deployments
3. Configure monitoring and alerting
4. Set up automated backups for PostgreSQL
5. Implement horizontal pod autoscaling based on metrics

## Support

For issues or questions about this deployment, refer to:
- PostgreSQL documentation: https://www.postgresql.org/docs/
- Kubernetes documentation: https://kubernetes.io/docs/
- GORM documentation: https://gorm.io/docs/

