package domain

import (
	"context"
	"fmt"
	"time"
)

// nolint (self documenting constants)
const (
	VulnStateLikely  = "LIKELY VULNERABLE"
	VulnStateNot     = "NOT VULNERABLE"
	VulnStateVuln    = "VULNERABLE"
	VulnStateDOS     = "VULNERABLE (DoS)"
	VulnStateExploit = "VULNERABLE (Exploitable)"
	VulnStateUnknown = "UNKNOWN (unable to test)"

	RiskFactorHigh   = "HIGH"
	RiskFactorMedium = "MEDIUM"
	RiskFactorLow    = "LOW"
)

// Vulnerability is a container that matches the output of any nmap library that
// uses the vulns module for reporting issues. There is no apparent documentation
// or contract for the library so this has been created based on the source
// code of the vulns module. Notably, the `local format_vuln_base` function
// was used.
type Vulnerability struct {
	// Unique identity of the vulnerability as reported by nmap.
	Key string
	// Title of the vulnerability.
	Title string
	// State of the vuln. One of the VulnState* constants.
	State string
	// External vulnerability database identifiers. (optional)
	IDs []VulnerabilityID
	// Short-hand severity rating. One of HIGH, MEDIUM, or LOW. (optional)
	RiskFactor string
	// Scores defined as CVSS or CVSSv2. (optional)
	Scores []VulnerabilityScore
	// Long form description of the issue. (optional)
	Description string
	// Critical dates associated with the vulnerability such as disclosure.
	// (optional)
	Dates []VulnerabilityDate
	// CheckResults contains any output relevant to the scan or probe that might
	// help diagnose or confirm the vulnerability state. (optional)
	CheckResults []string
	// ExploitResults contains any output gathered during an exploid of a
	// system. (optional)
	ExploitResults []string
	// ExtraInfo contains any arbitrary content from a scan or probe that does
	// not fit into other categories. (optional)
	ExtraInfo []string
	// References are external links to vulnerability databases or pages that
	// contain additional content about the vulnerability.
	References []string

	// Source is the script that generated the finding.
	Source string
	// Port on which the vulnerability was detected.
	Port int
	// Protocol used during network communications
	Protocol string
	// Service is the kind of application running on the port. Ex: http
	Service string
}

// VulnerabilityDate is used to describe when vulnerability conditions were
// reported or updated.
type VulnerabilityDate struct {
	// Type is the kind of date. Most commonly this is "disclosure".
	Type  string
	Year  int
	Month int
	Day   int
}

// VulnerabilityScore is a container of various forms of severity scoring. The
// most common entries are Type=CVSS and Type=CVSSv2.
type VulnerabilityScore struct {
	Type  string
	Value string
}

// VulnerabilityID is a container for typed identifiers. The most common entries
// are Type=CVE and Type=OSVDB.
type VulnerabilityID struct {
	Type  string
	Value string
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
	Scan(ctx context.Context, host string) ([]Finding, error)
}
