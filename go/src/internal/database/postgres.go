package database

import (
	"fmt"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// DB is the database connection.
type DB struct {
	*gorm.DB
}

// NewDB creates a new database connection.
func NewDB(dsn string) (*DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return &DB{db}, nil
}

// Migrate migrates the database schema.
func (db *DB) Migrate() error {
	err := db.AutoMigrate(&Target{}, &Scan{}, &Vulnerability{}, &Asset{})
	if err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	return nil
}
