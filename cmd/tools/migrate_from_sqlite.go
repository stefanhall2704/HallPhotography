package main

import (
	"fmt"
	"log"
	"os"

	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/stefanhall2704/GoPhotography/model"
)

func main() {
	fmt.Println("========================================")
	fmt.Println("SQLite to PostgreSQL Migration Tool")
	fmt.Println("========================================")
	fmt.Println()

	// Check if SQLite database exists
	if _, err := os.Stat("photography.db"); os.IsNotExist(err) {
		log.Fatal("❌ photography.db not found! Make sure you're running this from the project root.")
	}

	// Connect to SQLite
	fmt.Println("📂 Connecting to SQLite database...")
	sqliteDB, err := gorm.Open(sqlite.Open("photography.db"), &gorm.Config{})
	if err != nil {
		log.Fatalf("❌ Failed to connect to SQLite: %v", err)
	}
	fmt.Println("✅ Connected to SQLite")

	// Connect to PostgreSQL
	fmt.Println("📂 Connecting to PostgreSQL database...")
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		getEnv("DB_HOST", "localhost"),
		getEnv("DB_PORT", "5432"),
		getEnv("DB_USER", "hallphotography"),
		getEnv("DB_PASSWORD", "changeme"),
		getEnv("DB_NAME", "hallphotography"),
		getEnv("DB_SSLMODE", "disable"),
	)
	postgresDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("❌ Failed to connect to PostgreSQL: %v\n"+
			"Make sure PostgreSQL is running: docker-compose up -d postgres\n"+
			"Error: %v", err)
	}
	fmt.Println("✅ Connected to PostgreSQL")
	fmt.Println()

	// Get record counts from SQLite
	fmt.Println("📊 Checking SQLite database...")
	counts := getRecordCounts(sqliteDB)
	totalRecords := 0
	for _, count := range counts {
		totalRecords += count
	}

	if totalRecords == 0 {
		fmt.Println("⚠️  SQLite database is empty. Nothing to migrate.")
		return
	}

	fmt.Println()
	fmt.Printf("Found %d total records to migrate:\n", totalRecords)
	for table, count := range counts {
		if count > 0 {
			fmt.Printf("  - %s: %d records\n", table, count)
		}
	}
	fmt.Println()

	// Confirm migration
	fmt.Print("⚠️  This will OVERWRITE any existing data in PostgreSQL!\n")
	fmt.Print("Continue? (yes/no): ")
	var response string
	fmt.Scanln(&response)
	if response != "yes" && response != "y" {
		fmt.Println("❌ Migration cancelled.")
		return
	}
	fmt.Println()

	// Migrate data
	fmt.Println("🔄 Starting migration...")
	fmt.Println()

	migrateTable(sqliteDB, postgresDB, &model.User{}, "Users")
	migrateTable(sqliteDB, postgresDB, &model.Notification{}, "Notifications")
	migrateTable(sqliteDB, postgresDB, &model.Minis{}, "Minis")
	migrateTable(sqliteDB, postgresDB, &model.MinisDay{}, "MinisDay")
	migrateTable(sqliteDB, postgresDB, &model.Package{}, "Packages")
	migrateTable(sqliteDB, postgresDB, &model.Photo{}, "Photos")
	migrateTable(sqliteDB, postgresDB, &model.BookMinis{}, "BookMinis")
	migrateTable(sqliteDB, postgresDB, &model.Session{}, "Sessions")
	migrateTable(sqliteDB, postgresDB, &model.SessionDay{}, "SessionDay")
	migrateTable(sqliteDB, postgresDB, &model.BookSession{}, "BookSession")
	migrateTable(sqliteDB, postgresDB, &model.BookingMessage{}, "BookingMessages")
	migrateTable(sqliteDB, postgresDB, &model.SessionPhoto{}, "SessionPhotos")

	fmt.Println()
	fmt.Println("========================================")
	fmt.Println("✅ Migration completed successfully!")
	fmt.Println("========================================")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("1. Restart your application: docker-compose restart hallphotography")
	fmt.Println("2. Test that all data is accessible")
	fmt.Println("3. Keep photography.db as a backup")
	fmt.Println()
}

func migrateTable(from, to *gorm.DB, model interface{}, name string) {
	// Count records in source
	var count int64
	if err := from.Model(model).Count(&count).Error; err != nil {
		log.Printf("⚠️  Warning: Could not count %s: %v", name, err)
		return
	}

	if count == 0 {
		fmt.Printf("⏭️  Skipping %s (empty)\n", name)
		return
	}

	fmt.Printf("📦 Migrating %s (%d records)...\n", name, count)

	// Read all records from SQLite
	var records []map[string]interface{}
	if err := from.Model(model).Find(&records).Error; err != nil {
		log.Printf("❌ Error reading %s from SQLite: %v\n", name, err)
		return
	}

	// Write to PostgreSQL in batches
	batchSize := 100
	for i := 0; i < len(records); i += batchSize {
		end := i + batchSize
		if end > len(records) {
			end = len(records)
		}
		batch := records[i:end]

		if err := to.Model(model).Create(&batch).Error; err != nil {
			log.Printf("❌ Error writing batch to %s: %v\n", name, err)
			return
		}
	}

	fmt.Printf("   ✅ Successfully migrated %d %s records\n", count, name)
}

func getRecordCounts(db *gorm.DB) map[string]int {
	counts := make(map[string]int)

	tables := []struct {
		name  string
		model interface{}
	}{
		{"Users", &model.User{}},
		{"Notifications", &model.Notification{}},
		{"Minis", &model.Minis{}},
		{"MinisDay", &model.MinisDay{}},
		{"Packages", &model.Package{}},
		{"Photos", &model.Photo{}},
		{"BookMinis", &model.BookMinis{}},
		{"Sessions", &model.Session{}},
		{"SessionDay", &model.SessionDay{}},
		{"BookSession", &model.BookSession{}},
		{"BookingMessages", &model.BookingMessage{}},
		{"SessionPhotos", &model.SessionPhoto{}},
	}

	for _, table := range tables {
		var count int64
		db.Model(table.model).Count(&count)
		counts[table.name] = int(count)
	}

	return counts
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

