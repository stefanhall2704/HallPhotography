package model

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	gorm.Model
	FirstName       string `gorm:"not null"`
	LastName        string `gorm:"not null"`
	Username        string `gorm:"not null"`
	PasswordHash    string `gorm:"not null"`
	Email           string `gorm:"not null"`
	PhoneNumber     string `gorm:"not null"`
	IsAdmin         bool   `gorm:"default:false"`
	ProfilePicture  string `gorm:"default:''"` // Path to profile picture
	MinisSessions   string `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

type Notification struct {
	gorm.Model
	UserID      uint   `gorm:"not null;index"`
	Message     string `gorm:"not null"`
	Type        string `gorm:"not null"` // "booking", "update", "admin_notification"
	RelatedID   uint   // ID of related booking (BookMinis or BookSession)
	RelatedType string // "minis" or "session"
	IsRead      bool   `gorm:"default:false"`
	User        User   `gorm:"foreignKey:UserID"`
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
	Start       time.Time
	End         time.Time
	MinisID     uint
}

type BookMinis struct {
	gorm.Model
	MinisID              uint      `gorm:"not null"`
	UserID               uint      `gorm:"not null"`
	TimeSlot             string    `gorm:"not null"`
	Status               string    `gorm:"default:'pending'"` // "pending", "confirmed", "cancelled"
	ProposedTimeSlot     string    // Admin can propose alternative time
	ProposedPrice        float64   `gorm:"default:0"` // Price proposed by photographer
	PriceApprovalStatus  string    `gorm:"default:'pending'"` // "pending", "approved", "declined"
	HasPaid              bool      `gorm:"default:false"` // Payment status
	PaidAmount           float64   `gorm:"default:0"` // Amount paid
	PaymentDate          *time.Time // When payment was made
	PhotosUploaded       bool      `gorm:"default:false"` // Track if photos are uploaded
	DownloadLimit        int       `gorm:"default:0"` // How many photos the user can download (0 = all)
	User                 User      `gorm:"foreignKey:UserID"`
	Minis                Minis     `gorm:"foreignKey:MinisID"`
	Messages             []BookingMessage `gorm:"foreignKey:BookingID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
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

// Normal Session Models
type Session struct {
	gorm.Model
	Name             string        `gorm:"not null"`
	Description      string        `gorm:"not null"`
	DurationInterval string        `gorm:"not null"`
	Price            float64       `gorm:"not null"`
	Days             []SessionDay  `gorm:"foreignKey:SessionID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
	Bookings         []BookSession `gorm:"foreignKey:SessionID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`
}

type SessionDay struct {
	gorm.Model
	Start     time.Time
	End       time.Time
	SessionID uint
}

type BookSession struct {
	gorm.Model
	SessionID           uint    `gorm:"not null"`
	UserID              uint    `gorm:"not null"`
	TimeSlot            string  `gorm:"not null"`
	Status              string  `gorm:"default:'pending'"` // "pending", "confirmed", "cancelled", "awaiting_price_approval"
	ProposedTimeSlot    string  // Admin can propose alternative time
	ProposedPrice       float64 `gorm:"default:0"` // Price proposed by photographer
	PriceApprovalStatus string  `gorm:"default:'pending'"` // "pending", "approved", "declined"
	HasPaid             bool    `gorm:"default:false"` // Payment status
	PaidAmount          float64 `gorm:"default:0"` // Amount paid
	PaymentDate         *time.Time // When payment was made
	PhotosUploaded      bool    `gorm:"default:false"` // Track if photos are uploaded
	DownloadLimit       int     `gorm:"default:0"` // How many photos the user can download (0 = all)
	User                User    `gorm:"foreignKey:UserID"`
	Session             Session `gorm:"foreignKey:SessionID"`
	Messages            []BookingMessage `gorm:"foreignKey:BookingID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// BookingMessage represents a message in a booking conversation
type BookingMessage struct {
	gorm.Model
	BookingID   uint   `gorm:"not null;index"`
	BookingType string `gorm:"not null"` // "minis" or "session"
	UserID      uint   `gorm:"not null"`
	Message     string `gorm:"not null;type:text"`
	IsAdmin     bool   `gorm:"default:false"` // Track if message is from admin
	User        User   `gorm:"foreignKey:UserID"`
}

// SessionPhoto represents a photo uploaded by photographer for a booking
type SessionPhoto struct {
	gorm.Model
	BookingID       uint       `gorm:"not null;index"`
	BookingType     string     `gorm:"not null"` // "minis" or "session"
	FileName        string     `gorm:"not null"`
	FilePath        string     `gorm:"not null"`  // Path to original file on disk
	WatermarkedPath string     `gorm:"default:''"` // Path to watermarked version for viewing
	FileSize        int64      `gorm:"not null"`  // Size in bytes
	MimeType        string     `gorm:"not null"`  // image/jpeg, image/png, etc.
	IsFavorite      bool       `gorm:"default:false"` // User marked as favorite for download
	IsDownloaded    bool       `gorm:"default:false"` // Track if downloaded by user
	DownloadedAt    *time.Time // When it was downloaded
}

// PortfolioItem represents a portfolio item for the homepage gallery
type PortfolioItem struct {
	gorm.Model
	Title       string `gorm:"not null"`
	Description string `gorm:"type:text"`
	ImageURL    string `gorm:"not null"` // URL or path to the image
	Category    string `gorm:"not null"` // "portraits", "families", "events", etc.
	IsActive    bool   `gorm:"default:true"` // Whether to show on homepage
	SortOrder   int    `gorm:"default:0"` // For ordering items
}
