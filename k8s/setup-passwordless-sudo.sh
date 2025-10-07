#!/bin/bash
set -e

echo "========================================="
echo "Setting up passwordless sudo for cloudflared"
echo "========================================="
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "ERROR: Don't run this script as root. Run as your regular user."
    echo "The script will prompt for sudo password when needed."
    exit 1
fi

echo "This script will configure passwordless sudo for cloudflared systemctl commands."
echo "This is needed for automated deployments via GitHub Actions."
echo ""

# Create sudoers rule for cloudflared
echo "Creating sudoers rule for cloudflared..."
sudo tee /etc/sudoers.d/cloudflared > /dev/null << EOF
# Allow passwordless sudo for cloudflared systemctl commands
# This is needed for automated deployments
$USER ALL=(ALL) NOPASSWD: /bin/systemctl restart cloudflared
$USER ALL=(ALL) NOPASSWD: /bin/systemctl status cloudflared
$USER ALL=(ALL) NOPASSWD: /bin/systemctl reload cloudflared
EOF

echo "✅ Sudoers rule created successfully!"
echo ""

# Test the configuration
echo "Testing passwordless sudo for cloudflared..."
if sudo -n systemctl status cloudflared >/dev/null 2>&1; then
    echo "✅ Passwordless sudo is working correctly!"
else
    echo "❌ Passwordless sudo test failed. Please check the configuration."
    exit 1
fi

echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Your GitHub Actions deployment can now update Cloudflare tunnel configuration"
echo "without requiring a password prompt."
echo ""
echo "To verify, you can test:"
echo "  sudo systemctl status cloudflared"
echo "  sudo systemctl restart cloudflared"
echo ""
