#!/bin/bash

# Kubernetes Admin Setup Script
# This script helps you promote a user to admin on your Kubernetes cluster

echo "========================================"
echo "Kubernetes Admin Setup"
echo "========================================"
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl is not installed or not in PATH"
    echo "Please install kubectl and configure it for your cluster"
    exit 1
fi

echo "✅ kubectl found"
echo ""

# Get namespace (default to 'default' if not specified)
NAMESPACE=${1:-default}
echo "Using namespace: $NAMESPACE"
echo ""

# Function to find PostgreSQL pod
find_postgres_pod() {
    echo "🔍 Looking for PostgreSQL pod..."
    
    # Try different common PostgreSQL labels/names
    POSTGRES_POD=$(kubectl get pods -n $NAMESPACE -l app=postgres -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -z "$POSTGRES_POD" ]; then
        POSTGRES_POD=$(kubectl get pods -n $NAMESPACE -l app=postgresql -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    fi
    
    if [ -z "$POSTGRES_POD" ]; then
        POSTGRES_POD=$(kubectl get pods -n $NAMESPACE | grep -i postgres | awk '{print $1}' | head -1)
    fi
    
    if [ -z "$POSTGRES_POD" ]; then
        echo "❌ No PostgreSQL pod found in namespace '$NAMESPACE'"
        echo ""
        echo "Available pods:"
        kubectl get pods -n $NAMESPACE
        echo ""
        echo "Please specify the correct namespace or PostgreSQL pod name"
        exit 1
    fi
    
    echo "✅ Found PostgreSQL pod: $POSTGRES_POD"
}

# Function to promote user to admin
promote_user_to_admin() {
    local email=$1
    local postgres_pod=$2
    
    echo ""
    echo "🔧 Promoting user '$email' to admin..."
    
    # First, check if user exists
    echo "Checking if user exists..."
    kubectl exec -n $NAMESPACE $postgres_pod -- psql -U hallphotography -d hallphotography -c "SELECT id, email, first_name, last_name, is_admin FROM users WHERE email = '$email';"
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to connect to database or user not found"
        return 1
    fi
    
    echo ""
    echo "Promoting user to admin..."
    kubectl exec -n $NAMESPACE $postgres_pod -- psql -U hallphotography -d hallphotography -c "UPDATE users SET is_admin = true WHERE email = '$email';"
    
    if [ $? -eq 0 ]; then
        echo "✅ User promoted to admin successfully!"
        echo ""
        echo "Verifying change..."
        kubectl exec -n $NAMESPACE $postgres_pod -- psql -U hallphotography -d hallphotography -c "SELECT id, email, first_name, last_name, is_admin FROM users WHERE email = '$email';"
    else
        echo "❌ Failed to promote user to admin"
        return 1
    fi
}

# Function to create new admin user
create_admin_user() {
    local email=$1
    local first_name=$2
    local last_name=$3
    local password=$4
    local postgres_pod=$5
    
    echo ""
    echo "👤 Creating new admin user..."
    
    # Hash password using bcrypt (you'll need to install bcrypt or use a different method)
    # For now, we'll create a simple hash
    local hashed_password=$(echo -n "$password" | openssl dgst -sha256 | cut -d' ' -f2)
    
    kubectl exec -n $NAMESPACE $postgres_pod -- psql -U hallphotography -d hallphotography -c "
        INSERT INTO users (first_name, last_name, email, username, password_hash, is_admin, created_at, updated_at) 
        VALUES ('$first_name', '$last_name', '$email', '$email', '$hashed_password', true, NOW(), NOW())
        ON CONFLICT (email) DO UPDATE SET is_admin = true;
    "
    
    if [ $? -eq 0 ]; then
        echo "✅ Admin user created/updated successfully!"
    else
        echo "❌ Failed to create admin user"
        return 1
    fi
}

# Main execution
echo "Choose an option:"
echo "1. Promote existing user to admin"
echo "2. Create new admin user"
echo "3. List all users"
echo "4. Exit"
echo ""
read -p "Enter your choice (1-4): " choice

case $choice in
    1)
        read -p "Enter user email: " email
        if [ -z "$email" ]; then
            echo "❌ Email is required"
            exit 1
        fi
        
        find_postgres_pod
        promote_user_to_admin "$email" "$POSTGRES_POD"
        ;;
    2)
        read -p "Enter email: " email
        read -p "Enter first name: " first_name
        read -p "Enter last name: " last_name
        read -p "Enter password: " password
        
        if [ -z "$email" ] || [ -z "$first_name" ] || [ -z "$last_name" ] || [ -z "$password" ]; then
            echo "❌ All fields are required"
            exit 1
        fi
        
        find_postgres_pod
        create_admin_user "$email" "$first_name" "$last_name" "$password" "$POSTGRES_POD"
        ;;
    3)
        find_postgres_pod
        echo "📋 All users:"
        kubectl exec -n $NAMESPACE $POSTGRES_POD -- psql -U hallphotography -d hallphotography -c "SELECT id, email, first_name, last_name, is_admin FROM users ORDER BY id;"
        ;;
    4)
        echo "Goodbye!"
        exit 0
        ;;
    *)
        echo "❌ Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "========================================"
echo "✅ Setup complete!"
echo "========================================"
echo ""
echo "⚠️  Important: The user needs to log out and log back in for admin privileges to take effect!"
