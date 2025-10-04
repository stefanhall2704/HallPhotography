# Utility Tools

This directory contains utility scripts for managing the Hall Photography application.

## Available Tools

### check_admin.go

Lists all users in the database and their admin status.

**Usage:**
```bash
cd /home/stefan/Documents/Personal/HallPhotography
go run cmd/tools/check_admin.go
```

**Output:**
```
========================================
All Users and Their Admin Status:
========================================

ID: 1
Name: John Doe
Email: john@example.com
Username: john
Status: ✅ ADMIN
----------------------------------------

ID: 2
Name: Jane Smith
Email: jane@example.com
Username: jane
Status: ❌ Regular User
----------------------------------------
```

### set_admin.go

Sets a user as an administrator.

**Usage:**
```bash
cd /home/stefan/Documents/Personal/HallPhotography

# Using email
go run cmd/tools/set_admin.go user@example.com

# Using username
go run cmd/tools/set_admin.go username
```

**Examples:**
```bash
# Set user by email
go run cmd/tools/set_admin.go caitlin@hallphotography.com

# Set user by username
go run cmd/tools/set_admin.go caitlin
```

**Output:**
```
✅ Successfully set caitlin@hallphotography.com (Caitlin Hall) as admin!
User ID: 1

⚠️  Important: The user needs to log out and log back in for admin privileges to take effect!
```

## Important Notes

### Database Configuration

These tools use the same database configuration as the main application:
- Read from environment variables (`DB_HOST`, `DB_PORT`, etc.)
- Fall back to defaults if not set
- Use the same `db.ConnectDatabase()` function

Make sure your `.env` file is configured before running these tools:

```bash
# Copy example.env if you haven't already
cp example.env .env

# Edit with your database settings
nano .env
```

### Production Usage

**For Docker Compose:**
```bash
# Run tools inside the container
docker-compose exec hallphotography /bin/sh

# Then run the tool (you'll need to copy it to the container first)
```

**For Kubernetes:**
```bash
# Option 1: Run locally, pointing to production database
# Set environment variables to point to production DB
export DB_HOST=your-production-db-host
export DB_PORT=5432
export DB_USER=hallphotography
export DB_PASSWORD=your-password
export DB_NAME=hallphotography
export DB_SSLMODE=require

go run cmd/tools/check_admin.go
go run cmd/tools/set_admin.go user@example.com

# Option 2: Build and run in a pod
kubectl run admin-tool --rm -i --tty \
  --image=your-registry/hallphotography:latest \
  --command -- /bin/sh
```

### Security Considerations

- **Protect Access**: These tools directly modify the database
- **Production**: Only run by authorized administrators
- **Audit**: Log all admin privilege changes
- **Passwords**: Never store database passwords in scripts
- **Environment**: Use environment variables or Kubernetes secrets

## Adding New Tools

To add a new utility tool:

1. Create a new `.go` file in this directory
2. Use `package main` and create a `main()` function
3. Import necessary packages:
   ```go
   import (
       "github.com/stefanhall2704/GoPhotography/db"
       "github.com/stefanhall2704/GoPhotography/model"
   )
   ```
4. Use `db.ConnectDatabase()` to get the database connection
5. Document usage in this README

### Example Template

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/stefanhall2704/GoPhotography/db"
    "github.com/stefanhall2704/GoPhotography/model"
)

// Tool description and usage
func main() {
    database := db.ConnectDatabase()
    
    // Your tool logic here
    
    fmt.Println("Tool completed successfully!")
}
```

## Troubleshooting

### "Failed to connect to database"

**Problem**: Cannot connect to database

**Solutions:**
1. Check `.env` file exists and has correct settings
2. Verify database is running: `docker-compose ps`
3. Test database connection: `psql -h localhost -U hallphotography -d hallphotography`
4. Check environment variables: `env | grep DB_`

### "User not found"

**Problem**: Cannot find user by email or username

**Solutions:**
1. Run `check_admin.go` to see all users
2. Check spelling of email/username
3. Verify user exists in database

### "Already an admin"

**Info**: User already has admin privileges. This is not an error.

### Permission Denied

**Problem**: Cannot modify user in database

**Solutions:**
1. Check database user has write permissions
2. Verify database password is correct
3. Check database connection settings

## Alternative: Direct SQL

If tools are not working, you can also manage admins via SQL:

```sql
-- List all users
SELECT id, first_name, last_name, email, username, is_admin 
FROM users;

-- Set user as admin by email
UPDATE users SET is_admin = true WHERE email = 'user@example.com';

-- Set user as admin by ID
UPDATE users SET is_admin = true WHERE id = 1;

-- Remove admin privileges
UPDATE users SET is_admin = false WHERE email = 'user@example.com';
```

**Using psql:**
```bash
# Local Docker
docker exec -it hallphotography-db psql -U hallphotography

# Then run SQL commands
hallphotography=# UPDATE users SET is_admin = true WHERE email = 'user@example.com';
```

