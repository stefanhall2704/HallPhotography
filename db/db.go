package db

import (
	"log"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/stefanhall2704/GoPhotography/model"
)

func ConnectDatabase() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("./photography.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	// AutoMigrate will create or migrate the User table based on your User model
	// Now checking for error returned by AutoMigrate
	if err := db.AutoMigrate(&model.User{}, &model.Document{}); err != nil {
		log.Fatalf("Failed to auto-migrate User table: %v", err)
	}

	return db
}
