# SQLite to PostgreSQL Migration Guide

This guide will help you migrate your existing SQLite database to PostgreSQL.

## Prerequisites

- Existing SQLite database file (`photography.db`)
- PostgreSQL server running and accessible
- `pgloader` tool installed (recommended method)

## Method 1: Using pgloader (Recommended)

`pgloader` is a data loading tool that can migrate from SQLite to PostgreSQL automatically.

### Install pgloader

```bash
# Ubuntu/Debian
sudo apt-get install pgloader

# macOS
brew install pgloader

# Arch Linux
yay -S pgloader
```

### Create Migration Configuration

Create a file named `migration.load`:

```lisp
LOAD DATABASE
     FROM sqlite://photography.db
     INTO postgresql://hallphotography:changeme@localhost:5432/hallphotography

WITH include drop, create tables, create indexes, reset sequences

SET work_mem to '16MB', maintenance_work_mem to '512 MB';
```

### Run Migration

```bash
pgloader migration.load
```

### Verify Migration

```bash
# Connect to PostgreSQL
psql -U hallphotography -d hallphotography

# List tables
\dt

# Check row counts
SELECT 'users' as table_name, COUNT(*) FROM users
UNION ALL
SELECT 'notifications', COUNT(*) FROM notifications
UNION ALL
SELECT 'minis', COUNT(*) FROM minis
UNION ALL
SELECT 'minis_days', COUNT(*) FROM minis_days
UNION ALL
SELECT 'packages', COUNT(*) FROM packages
UNION ALL
SELECT 'photos', COUNT(*) FROM photos
UNION ALL
SELECT 'book_minis', COUNT(*) FROM book_minis
UNION ALL
SELECT 'sessions', COUNT(*) FROM sessions
UNION ALL
SELECT 'session_days', COUNT(*) FROM session_days
UNION ALL
SELECT 'book_sessions', COUNT(*) FROM book_sessions
UNION ALL
SELECT 'booking_messages', COUNT(*) FROM booking_messages
UNION ALL
SELECT 'session_photos', COUNT(*) FROM session_photos;
```

## Method 2: Manual Export/Import

If pgloader is not available, you can manually export and import data.

### Step 1: Export from SQLite

Create a script `export_sqlite.sh`:

```bash
#!/bin/bash

SQLITE_DB="photography.db"
OUTPUT_DIR="sqlite_export"

mkdir -p $OUTPUT_DIR

# Export tables as CSV
sqlite3 $SQLITE_DB <<EOF
.headers on
.mode csv
.output ${OUTPUT_DIR}/users.csv
SELECT * FROM users;
.output ${OUTPUT_DIR}/notifications.csv
SELECT * FROM notifications;
.output ${OUTPUT_DIR}/minis.csv
SELECT * FROM minis;
.output ${OUTPUT_DIR}/minis_days.csv
SELECT * FROM minis_days;
.output ${OUTPUT_DIR}/packages.csv
SELECT * FROM packages;
.output ${OUTPUT_DIR}/photos.csv
SELECT * FROM photos;
.output ${OUTPUT_DIR}/book_minis.csv
SELECT * FROM book_minis;
.output ${OUTPUT_DIR}/sessions.csv
SELECT * FROM sessions;
.output ${OUTPUT_DIR}/session_days.csv
SELECT * FROM session_days;
.output ${OUTPUT_DIR}/book_sessions.csv
SELECT * FROM book_sessions;
.output ${OUTPUT_DIR}/booking_messages.csv
SELECT * FROM booking_messages;
.output ${OUTPUT_DIR}/session_photos.csv
SELECT * FROM session_photos;
EOF

echo "Export completed. Files are in $OUTPUT_DIR/"
```

```bash
chmod +x export_sqlite.sh
./export_sqlite.sh
```

### Step 2: Prepare PostgreSQL

```bash
# Start PostgreSQL (if using Docker Compose)
docker-compose up -d postgres

# Wait for PostgreSQL to be ready
sleep 5

# Run the application once to create tables
# Or manually run migrations
```

### Step 3: Import to PostgreSQL

Create a script `import_postgres.sh`:

```bash
#!/bin/bash

DB_HOST="localhost"
DB_PORT="5432"
DB_USER="hallphotography"
DB_PASSWORD="changeme"
DB_NAME="hallphotography"
INPUT_DIR="sqlite_export"

export PGPASSWORD=$DB_PASSWORD

# Function to import CSV
import_table() {
    local table=$1
    local file="${INPUT_DIR}/${table}.csv"
    
    if [ -f "$file" ]; then
        echo "Importing $table..."
        psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "\COPY $table FROM '$file' WITH (FORMAT csv, HEADER true)"
    else
        echo "Warning: $file not found, skipping $table"
    fi
}

# Import in correct order (respecting foreign keys)
import_table "users"
import_table "notifications"
import_table "minis"
import_table "minis_days"
import_table "packages"
import_table "photos"
import_table "book_minis"
import_table "sessions"
import_table "session_days"
import_table "book_sessions"
import_table "booking_messages"
import_table "session_photos"

# Reset sequences
echo "Resetting sequences..."
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME <<EOF
SELECT setval('users_id_seq', (SELECT MAX(id) FROM users));
SELECT setval('notifications_id_seq', (SELECT MAX(id) FROM notifications));
SELECT setval('minis_id_seq', (SELECT MAX(id) FROM minis));
SELECT setval('minis_days_id_seq', (SELECT MAX(id) FROM minis_days));
SELECT setval('packages_id_seq', (SELECT MAX(id) FROM packages));
SELECT setval('photos_id_seq', (SELECT MAX(id) FROM photos));
SELECT setval('book_minis_id_seq', (SELECT MAX(id) FROM book_minis));
SELECT setval('sessions_id_seq', (SELECT MAX(id) FROM sessions));
SELECT setval('session_days_id_seq', (SELECT MAX(id) FROM session_days));
SELECT setval('book_sessions_id_seq', (SELECT MAX(id) FROM book_sessions));
SELECT setval('booking_messages_id_seq', (SELECT MAX(id) FROM booking_messages));
SELECT setval('session_photos_id_seq', (SELECT MAX(id) FROM session_photos));
EOF

echo "Import completed!"
```

```bash
chmod +x import_postgres.sh
./import_postgres.sh
```

## Method 3: Using GORM (Go Application)

Create a temporary migration tool `tools/migrate.go`:

```go
package main

import (
    "log"
    
    "gorm.io/driver/sqlite"
    "gorm.io/driver/postgres"
    "gorm.io/gorm"
    
    "github.com/stefanhall2704/GoPhotography/model"
)

func main() {
    // Connect to SQLite
    sqliteDB, err := gorm.Open(sqlite.Open("photography.db"), &gorm.Config{})
    if err != nil {
        log.Fatalf("Failed to connect to SQLite: %v", err)
    }
    
    // Connect to PostgreSQL
    dsn := "host=localhost port=5432 user=hallphotography password=changeme dbname=hallphotography sslmode=disable"
    postgresDB, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
    if err != nil {
        log.Fatalf("Failed to connect to PostgreSQL: %v", err)
    }
    
    // Migrate schema
    log.Println("Creating PostgreSQL schema...")
    postgresDB.AutoMigrate(
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
    )
    
    // Migrate data
    migrateTable(sqliteDB, postgresDB, &model.User{})
    migrateTable(sqliteDB, postgresDB, &model.Notification{})
    migrateTable(sqliteDB, postgresDB, &model.Minis{})
    migrateTable(sqliteDB, postgresDB, &model.MinisDay{})
    migrateTable(sqliteDB, postgresDB, &model.Package{})
    migrateTable(sqliteDB, postgresDB, &model.Photo{})
    migrateTable(sqliteDB, postgresDB, &model.BookMinis{})
    migrateTable(sqliteDB, postgresDB, &model.Session{})
    migrateTable(sqliteDB, postgresDB, &model.SessionDay{})
    migrateTable(sqliteDB, postgresDB, &model.BookSession{})
    migrateTable(sqliteDB, postgresDB, &model.BookingMessage{})
    migrateTable(sqliteDB, postgresDB, &model.SessionPhoto{})
    
    log.Println("Migration completed successfully!")
}

func migrateTable(from, to *gorm.DB, model interface{}) {
    // Get table name
    stmt := &gorm.Statement{DB: to}
    stmt.Parse(model)
    tableName := stmt.Schema.Table
    
    log.Printf("Migrating %s...", tableName)
    
    // Read from SQLite
    var records []map[string]interface{}
    if err := from.Model(model).Find(&records).Error; err != nil {
        log.Printf("Error reading from %s: %v", tableName, err)
        return
    }
    
    // Write to PostgreSQL
    for _, record := range records {
        if err := to.Model(model).Create(&record).Error; err != nil {
            log.Printf("Error writing to %s: %v", tableName, err)
        }
    }
    
    log.Printf("Migrated %d records from %s", len(records), tableName)
}
```

**Note**: This method requires temporarily adding SQLite driver back to go.mod:

```bash
go get gorm.io/driver/sqlite@v1.5.6
go run tools/migrate.go
go mod tidy  # Remove SQLite after migration
```

## Post-Migration Steps

### 1. Verify Data Integrity

```sql
-- Check foreign key relationships
SELECT 
    conname AS constraint_name,
    conrelid::regclass AS table_name,
    confrelid::regclass AS referenced_table
FROM pg_constraint
WHERE confrelid IS NOT NULL;

-- Check for null values in NOT NULL columns
-- (Example for users table)
SELECT COUNT(*) FROM users WHERE first_name IS NULL OR last_name IS NULL;
```

### 2. Update Application Configuration

```bash
# Update .env file with PostgreSQL settings
DB_HOST=localhost
DB_PORT=5432
DB_USER=hallphotography
DB_PASSWORD=changeme
DB_NAME=hallphotography
DB_SSLMODE=disable
```

### 3. Test Application

```bash
# Start the application
docker-compose up

# Test critical functionality:
# - User login
# - View bookings
# - Upload photos
# - View photos
# - Admin functions
```

### 4. Backup

```bash
# Create a backup of PostgreSQL database
pg_dump -h localhost -U hallphotography -d hallphotography > backup_$(date +%Y%m%d).sql

# Or using Docker
docker exec hallphotography-db pg_dump -U hallphotography hallphotography > backup_$(date +%Y%m%d).sql
```

## Common Issues and Solutions

### Issue: Foreign Key Violations

**Problem**: Import fails due to foreign key constraints

**Solution**: 
1. Disable foreign key checks temporarily:
   ```sql
   SET session_replication_role = 'replica';
   -- Import data
   SET session_replication_role = 'origin';
   ```

2. Or import in correct order (parent tables first)

### Issue: Sequence Not Updated

**Problem**: New inserts fail with "duplicate key value"

**Solution**: Reset sequences as shown in the import script above

### Issue: Binary Data (Photos)

**Problem**: Photo data not importing correctly

**Solution**: 
- Use `bytea` type in PostgreSQL (already configured in model)
- Ensure binary data is properly encoded during export/import
- Consider storing photos as files and only storing paths in database

### Issue: Timezone Differences

**Problem**: Timestamps are different after migration

**Solution**:
- PostgreSQL uses timezone-aware timestamps by default
- SQLite uses UTC
- Verify timestamp columns after migration:
  ```sql
  SELECT id, created_at, updated_at FROM users LIMIT 10;
  ```

## Rollback Plan

If migration fails:

1. Keep SQLite database as backup
2. Drop PostgreSQL database and recreate:
   ```sql
   DROP DATABASE hallphotography;
   CREATE DATABASE hallphotography;
   ```
3. Try migration again with corrected issues
4. Or temporarily revert to SQLite (see CHANGELOG_PRODUCTION.md)

## Performance Optimization After Migration

```sql
-- Analyze tables for query optimization
ANALYZE;

-- Create additional indexes if needed
CREATE INDEX idx_book_minis_user_id ON book_minis(user_id);
CREATE INDEX idx_book_sessions_user_id ON book_sessions(user_id);
CREATE INDEX idx_notifications_user_id_is_read ON notifications(user_id, is_read);
CREATE INDEX idx_session_photos_booking ON session_photos(booking_id, booking_type);

-- Vacuum database
VACUUM ANALYZE;
```

## Final Checklist

- [ ] All tables migrated successfully
- [ ] Row counts match between SQLite and PostgreSQL
- [ ] Foreign key relationships intact
- [ ] Sequences reset correctly
- [ ] Application connects to PostgreSQL
- [ ] User authentication works
- [ ] Bookings can be created and viewed
- [ ] Photos can be uploaded and downloaded
- [ ] Admin functions work
- [ ] Backup created
- [ ] SQLite database archived safely

## Need Help?

If you encounter issues:
1. Check application logs: `docker-compose logs -f hallphotography`
2. Check PostgreSQL logs: `docker-compose logs -f postgres`
3. Verify database connection: `docker exec -it hallphotography-db psql -U hallphotography`
4. Refer to DEPLOYMENT.md for troubleshooting

