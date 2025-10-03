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

	// Now checking for error returned by AutoMigrate
	if err := db.AutoMigrate(&model.User{}, &model.Notification{}, &model.Minis{}, &model.MinisDay{}, &model.Package{}, &model.Photo{}, &model.BookMinis{}, &model.Session{}, &model.SessionDay{}, &model.BookSession{}, &model.BookingMessage{}, &model.SessionPhoto{}); err != nil {
		log.Fatalf("Failed to auto-migrate database: %v", err)
	}

	return db
}
