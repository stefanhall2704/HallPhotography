package model

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	gorm.Model
	FirstName    string `gorm:"not null"`
	LastName     string `gorm:"not null"`
	Username     string `gorm:"not null"`
	PasswordHash string `gorm:"not null"`
	Email        string `gorm:"not null"`
	PhoneNumber  string `gorm:"not null"`
	MinisSessions string `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

type Minis struct {
	gorm.Model
	Name             string      `gorm:"not null"`
	Description      string      `gorm:"not null"`
	DurationInterval string      `gorm:"not null"`
	Days             []MinisDay  `gorm:"foreignKey:MinisID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	Sessions         []BookMinis `gorm:"foreignKey:MinisID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

type MinisDay struct {
	gorm.Model
	DayForMinis time.Time
	MinisID     uint
}

type BookMinis struct {
	gorm.Model
	MinisID  uint   `gorm:"not null"`
	UserID   uint   `gorm:"not null"`
	TimeSlot string `gorm:"not null"`
}

type Package struct {
	gorm.Model
	Name        string `gorm:"not null"`
	Description string `gorm:"not null"`
	Photo       Photo  `gorm:"foreignKey:PackageID"`
}

type Photo struct {
	gorm.Model
	ContentType string
	Data        []byte `gorm:"type:bytea"`
	PackageID   uint   `gorm:"uniqueIndex"`
}
