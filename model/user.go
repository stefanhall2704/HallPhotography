package model

import (
	"time"

	"gorm.io/gorm"
)

type Document struct {
	gorm.Model
	FileName    string `gorm:"type:varchar(100);"`
	ContentType string `gorm:"type:text;"`
	OwnerID     uint   `gorm:"not null"`
	Share       bool   `gorm:"not null"`
	LastEdit    time.Time
	Users       []User `gorm:"many2many:shared_documents;"`
}

type User struct {
	gorm.Model
	Username        string     `gorm:"not null"`
	PasswordHash    string     `gorm:"not null"`
	Email           string     `gorm:"not null"`
	Documents       []Document `gorm:"foreignKey:OwnerID"`
	SharedDocuments []Document `gorm:"many2many:shared_documents;"`
}
