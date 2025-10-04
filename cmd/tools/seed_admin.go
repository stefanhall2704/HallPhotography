package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/bcrypt"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("Admin User Seed Script")
	fmt.Println("========================================")
	fmt.Println()

	// Get admin details from command line or use defaults
	email := getEnvOrPrompt("ADMIN_EMAIL", "Enter admin email")
	firstName := getEnvOrPrompt("ADMIN_FIRST_NAME", "Enter first name")
	lastName := getEnvOrPrompt("ADMIN_LAST_NAME", "Enter last name")
	password := getEnvOrPrompt("ADMIN_PASSWORD", "Enter password")
	phone := getEnvOrDefault("ADMIN_PHONE", "")

	if email == "" || firstName == "" || lastName == "" || password == "" {
		log.Fatal("❌ Email, first name, last name, and password are required!")
	}

	// Connect to database
	fmt.Println("📂 Connecting to database...")
	database := db.GetDB()
	fmt.Println("✅ Connected to database")
	
	// Ensure tables exist
	fmt.Println("🔧 Running database migrations...")
	if err := db.MigrateDatabase(); err != nil {
		log.Fatalf("❌ Failed to migrate database: %v", err)
	}
	fmt.Println("✅ Database tables ready")
	fmt.Println()

	// Check if admin user already exists
	var existingUser model.User
	err := database.Where("email = ?", email).First(&existingUser).Error
	if err == nil {
		fmt.Printf("ℹ️  User with email %s already exists (ID: %d)\n", email, existingUser.ID)
		
		if existingUser.IsAdmin {
			fmt.Println("✅ User is already an admin!")
		} else {
			fmt.Print("User is not an admin. Promote to admin? (yes/no): ")
			var response string
			fmt.Scanln(&response)
			if response == "yes" || response == "y" {
				existingUser.IsAdmin = true
				if err := database.Save(&existingUser).Error; err != nil {
					log.Fatalf("❌ Error promoting user: %v", err)
				}
				fmt.Println("✅ User promoted to admin!")
			}
		}
		return
	}

	// Hash the password
	fmt.Println("🔐 Hashing password...")
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("❌ Error hashing password: %v", err)
	}

	// Create admin user
	adminUser := model.User{
		FirstName:    firstName,
		LastName:     lastName,
		Email:        email,
		Username:     email, // Use email as username
		PasswordHash: string(hashedPassword),
		PhoneNumber:  phone,
		IsAdmin:      true,
	}

	fmt.Println("👤 Creating admin user...")
	if err := database.Create(&adminUser).Error; err != nil {
		log.Fatalf("❌ Error creating admin user: %v", err)
	}

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("✅ Admin user created successfully!")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Printf("Email: %s\n", email)
	fmt.Printf("Name: %s %s\n", firstName, lastName)
	fmt.Printf("User ID: %d\n", adminUser.ID)
	fmt.Println()
	fmt.Println("You can now log in with:")
	fmt.Printf("  Email: %s\n", email)
	fmt.Printf("  Password: %s\n", password)
	fmt.Println()
	fmt.Println("⚠️  Important: Change your password after first login!")
	fmt.Println()
}

func getEnvOrPrompt(envKey, prompt string) string {
	// Check environment variable first
	value := os.Getenv(envKey)
	if value != "" {
		return value
	}

	// Prompt user
	fmt.Printf("%s: ", prompt)
	var input string
	fmt.Scanln(&input)
	return input
}

func getEnvOrDefault(envKey, defaultValue string) string {
	value := os.Getenv(envKey)
	if value != "" {
		return value
	}
	return defaultValue
}

