package database

import (
	"time"
)

// Target represents a target to be scanned.
type Target struct {
	ID        int       `json:"id"`
	URL       string    `json:"url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Scan represents a single scan of a target.
type Scan struct {
	ID        int       `json:"id"`
	TargetID  int       `json:"target_id"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Vulnerability represents a single vulnerability found during a scan.
type Vulnerability struct {
	ID          int       `json:"id"`
	ScanID      int       `json:"scan_id"`
	Plugin      string    `json:"plugin"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Asset represents a single asset discovered during a scan.
type Asset struct {
	ID        int       `json:"id"`
	ScanID    int       `json:"scan_id"`
	Type      string    `json:"type"`
	Value     string    `json:"value"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
