package domain

import (
	"context"
	"fmt"
	"time"
)

// Vulnerability contains the core information related to the kind of
// vulnerability detected. There may be any number of these in a given Finding.
type Vulnerability struct {
	// ID of the vulnerability. This should be a CVE value if possible.
	ID string
	// Description of the vulnerability.
	Description string
	// Product value that matched the vulnerability.
	Product string
	// ProductVersion is the detected version of the system running that
	// appears vulnerable.
	ProductVersion string
	// Link to the associated CVE or other information.
	Link string

	// Source is the script that generated the finding.
	Source string
	// Port on which the vulnerability was detected.
	Port int
	// Protocol used during network communications
	Protocol string
	// Service is the kind of application running on the port. Ex: http
	Service string
}

// Finding is a set detected vulnerability for a specific system.
type Finding struct {
	// Timestamp is when the finding was detected.
	Timestamp time.Time
	// IP is the address that was scanned.
	IP string
	// Hostnames are optionally included names that resolve to the scan IP.
	Hostnames       []string
	Vulnerabilities []Vulnerability
}

// MissingScanTargetError represents cases where the given host or IP for a scan
// cannot be found.
type MissingScanTargetError struct {
	Target string
}

func (e MissingScanTargetError) Error() string {
	return fmt.Sprintf("no scan targets found for %s", e.Target)
}

// Scanner represents a system that will probe the given host and determine
// if there are any vulnerable components.
type Scanner interface {
	Scan(ctx context.Context, host string) (Finding, error)
}
