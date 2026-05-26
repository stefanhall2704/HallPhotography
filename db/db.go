package db

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/stefanhall2704/GoPhotography/model"
)

var (
	db   *gorm.DB
	once sync.Once
)

// GetDB returns the singleton database instance
func GetDB() *gorm.DB {
	once.Do(func() {
		var err error
		db, err = initDB()
		if err != nil {
			log.Fatalf("Failed to connect to database: %v", err)
		}
		log.Println("Database connection established successfully")
	})
	return db
}

// initDB initializes the database connection with connection pooling
func initDB() (*gorm.DB, error) {
	// Get database configuration from environment variables
	dbHost := getEnv("DB_HOST", "localhost")
	dbPort := getEnv("DB_PORT", "5432")
	dbUser := getEnv("DB_USER", "hallphotography")
	dbPassword := getEnv("DB_PASSWORD", "")
	dbName := getEnv("DB_NAME", "hallphotography")
	dbSSLMode := getEnv("DB_SSLMODE", "disable")

	// Construct DSN (Data Source Name)
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		dbHost, dbPort, dbUser, dbPassword, dbName, dbSSLMode)

	// Configure GORM
	config := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	}

	// Open database connection
	database, err := gorm.Open(postgres.Open(dsn), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Get underlying SQL database to configure connection pool
	sqlDB, err := database.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get database instance: %w", err)
	}

	// Configure connection pool for production
	// Maximum number of open connections to the database
	sqlDB.SetMaxOpenConns(25)

	// Maximum number of idle connections in the pool
	sqlDB.SetMaxIdleConns(5)

	// Maximum lifetime of a connection
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	// Maximum idle time of a connection
	sqlDB.SetConnMaxIdleTime(10 * time.Minute)

	// Test the connection
	if err := sqlDB.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	return database, nil
}

// ConnectDatabase maintains backward compatibility with existing code
// It returns the singleton database instance
func ConnectDatabase() *gorm.DB {
	return GetDB()
}

// MigrateDatabase runs database migrations
func MigrateDatabase() error {
	database := GetDB()
	if err := database.AutoMigrate(
		&model.User{},
		&model.Notification{},
		&model.Minis{},
		&model.MinisDay{},
		&model.Package{},
		&model.Photo{},
		&model.BookMinis{},
		&model.Session{},
		&model.SessionDay{},
		&model.BookSession{},
		&model.BookingMessage{},
		&model.SessionPhoto{},
		&model.PortfolioItem{},
		&model.PendingCustomer{},
	); err != nil {
		return err
	}

	// Drop user FK constraints on booking tables so offline bookings (UserID=0, unclaimed)
	// can be inserted without violating referential integrity. Ownership is enforced in handlers.
	database.Exec("ALTER TABLE book_sessions DROP CONSTRAINT IF EXISTS fk_book_sessions_user")
	database.Exec("ALTER TABLE book_minis DROP CONSTRAINT IF EXISTS fk_book_minis_user")

	return nil
}

// CloseDatabase closes the database connection gracefully
func CloseDatabase() error {
	if db != nil {
		sqlDB, err := db.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}

// getEnv gets an environment variable with a default value
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}
