package main

import (
	"fmt"
	"log"

	"github.com/stefanhall2704/GoPhotography/db"
	"github.com/stefanhall2704/GoPhotography/model"
)

// Helper script to check and list all users and their admin status
// Usage: go run check_admin.go

func main() {
	database := db.ConnectDatabase()
	
	var users []model.User
	if err := database.Find(&users).Error; err != nil {
		log.Fatalf("Error fetching users: %v", err)
	}

	fmt.Println("========================================")
	fmt.Println("All Users and Their Admin Status:")
	fmt.Println("========================================")
	
	for _, user := range users {
		adminStatus := "❌ Regular User"
		if user.IsAdmin {
			adminStatus = "✅ ADMIN"
		}
		fmt.Printf("\nID: %d\n", user.ID)
		fmt.Printf("Name: %s %s\n", user.FirstName, user.LastName)
		fmt.Printf("Email: %s\n", user.Email)
		fmt.Printf("Username: %s\n", user.Username)
		fmt.Printf("Status: %s\n", adminStatus)
		fmt.Println("----------------------------------------")
	}
	
	fmt.Println("\n========================================")
	fmt.Println("To set a user as admin, run:")
	fmt.Println("go run set_admin.go <email>")
	fmt.Println("========================================")
}

