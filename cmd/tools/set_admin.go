package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

// Helper script to set a user as admin
// Usage: go run set_admin.go <email_or_username>
// Example: go run set_admin.go caitlin@hallphotography.com
// Example: go run set_admin.go caitlin

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run set_admin.go <email_or_username>")
		fmt.Println("Example: go run set_admin.go caitlin@hallphotography.com")
		fmt.Println("Example: go run set_admin.go caitlin")
		fmt.Println("\nRun 'go run check_admin.go' to see all users")
		os.Exit(1)
	}

	identifier := os.Args[1]
	
	database := db.ConnectDatabase()
	
	var user model.User
	var err error
	
	// Try to find by email first
	if strings.Contains(identifier, "@") {
		err = database.Where("email = ?", identifier).First(&user).Error
	} else {
		// Try username
		err = database.Where("username = ?", identifier).First(&user).Error
	}
	
	if err != nil {
		log.Fatalf("❌ User with identifier '%s' not found.\n\nRun 'go run check_admin.go' to see all users.\nError: %v", identifier, err)
	}

	// Check if already admin
	if user.IsAdmin {
		fmt.Printf("ℹ️  %s (%s %s) is already an admin!\n", user.Email, user.FirstName, user.LastName)
		fmt.Printf("User ID: %d\n", user.ID)
		os.Exit(0)
	}

	user.IsAdmin = true
	if err := database.Save(&user).Error; err != nil {
		log.Fatalf("❌ Error updating user: %v", err)
	}

	fmt.Printf("✅ Successfully set %s (%s %s) as admin!\n", user.Email, user.FirstName, user.LastName)
	fmt.Printf("User ID: %d\n", user.ID)
	fmt.Println("\n⚠️  Important: The user needs to log out and log back in for admin privileges to take effect!")
}

