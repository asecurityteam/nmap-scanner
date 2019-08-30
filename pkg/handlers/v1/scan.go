package v1

import (
	"context"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/asecurityteam/nmap-scanner/pkg/logs"
)

// ScanInput is a container for the JSON request body.
type ScanInput struct {
	Host string `json:"host"`
}

// ScanVulnerability is a JSON domain.Vulnerability.
type ScanVulnerability struct {
	// Unique identity of the vulnerability as reported by nmap.
	Key string `json:"key"`
	// Title of the vulnerability.
	Title string `json:"title"`
	// State of the vuln. One of the VulnState* constants.
	State string `json:"state"`
	// External vulnerability database identifiers. (optional)
	IDs []ScanVulnerabilityID `json:"ids"`
	// Short-hand severity rating. One of HIGH, MEDIUM, or LOW. (optional)
	RiskFactor string `json:"riskFactor"`
	// Scores defined as CVSS or CVSSv2. (optional)
	Scores []ScanVulnerabilityScore `json:"scores"`
	// Long form description of the issue. (optional)
	Description string `json:"description"`
	// Critical dates associated with the vulnerability such as disclosure.
	// (optional)
	Dates []ScanVulnerabilityDate `json:"dates"`
	// CheckResults contains any output relevant to the scan or probe that might
	// help diagnose or confirm the vulnerability state. (optional)
	CheckResults []string `json:"checkResults"`
	// ExploitResults contains any output gathered during an exploit of a
	// system. (optional)
	ExploitResults []string `json:"exploitResults"`
	// ExtraInfo contains any arbitrary content from a scan or probe that does
	// not fit into other categories. (optional)
	ExtraInfo []string `json:"extraInfo"`
	// References are external links to vulnerability databases or pages that
	// contain additional content about the vulnerability.
	References []string `json:"references"`

	// Source is the script that generated the finding.
	Source string `json:"source"`
	// Port on which the vulnerability was detected.
	Port int `json:"port"`
	// Protocol used during network communications
	Protocol string `json:"protocol"`
	// Service is the kind of application running on the port. Ex: http
	Service string `json:"service"`
}

// ScanVulnerabilityDate is a JSON domain.VulnerabilityDate.
type ScanVulnerabilityDate struct {
	Type  string `json:"type"`
	Year  int    `json:"year"`
	Month int    `json:"month"`
	Day   int    `json:"day"`
}

// ScanVulnerabilityScore is a JSON domain.VulnerabilityScore.
type ScanVulnerabilityScore struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ScanVulnerabilityID is a JSON domain.VulnerabilityID.
type ScanVulnerabilityID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ScanFinding is a JSON domain.Finding.
type ScanFinding struct {
	// Timestamp is when the finding was detected.
	Timestamp time.Time `json:"timestamp"`
	// IP is the address that was scanned.
	IP string `json:"ip"`
	// Hostnames are optionally included names that resolve to the scan IP.
	Hostnames       []string            `json:"hostnames"`
	Vulnerabilities []ScanVulnerability `json:"vulnerabilities"`
}

func scanVulnerabilityFromDomain(source domain.Vulnerability) ScanVulnerability {
	v := ScanVulnerability{
		Key:            source.Key,
		Title:          source.Title,
		State:          source.State,
		IDs:            make([]ScanVulnerabilityID, 0, len(source.IDs)),
		RiskFactor:     source.RiskFactor,
		Scores:         make([]ScanVulnerabilityScore, 0, len(source.Scores)),
		Description:    source.Description,
		Dates:          make([]ScanVulnerabilityDate, 0, len(source.Dates)),
		CheckResults:   source.CheckResults,
		ExploitResults: source.ExploitResults,
		ExtraInfo:      source.ExtraInfo,
		References:     source.References,
		Source:         source.Source,
		Port:           source.Port,
		Protocol:       source.Protocol,
		Service:        source.Service,
	}
	for _, id := range source.IDs {
		v.IDs = append(v.IDs, ScanVulnerabilityID(id))
	}
	for _, score := range source.Scores {
		v.Scores = append(v.Scores, ScanVulnerabilityScore(score))
	}
	for _, date := range source.Dates {
		v.Dates = append(v.Dates, ScanVulnerabilityDate(date))
	}

	return v
}

func scanFindingFromDomain(source domain.Finding) ScanFinding {
	f := ScanFinding{
		Timestamp:       source.Timestamp,
		IP:              source.IP,
		Hostnames:       source.Hostnames,
		Vulnerabilities: make([]ScanVulnerability, 0, len(source.Vulnerabilities)),
	}
	for _, v := range source.Vulnerabilities {
		f.Vulnerabilities = append(f.Vulnerabilities, scanVulnerabilityFromDomain(v))
	}
	return f
}

func fromDomain(source []domain.Finding) []ScanFinding {
	r := make([]ScanFinding, 0, len(source))
	for _, s := range source {
		r = append(r, scanFindingFromDomain(s))
	}
	return r
}

// Scan is a handler that manages scanning a host on-deman.
type Scan struct {
	LogFn    domain.LogFn
	Scanner  domain.Scanner
	Producer domain.Producer
}

func (h *Scan) handle(ctx context.Context, in ScanInput) ([]ScanFinding, error) {
	findings, err := h.Scanner.Scan(ctx, in.Host)
	if err != nil {
		return nil, err
	}
	return fromDomain(findings), nil
}

// Handle is invoked on each request.
func (h *Scan) Handle(ctx context.Context, in ScanInput) (interface{}, error) {
	v, err := h.handle(ctx, in)
	if err != nil {
		h.LogFn(ctx).Error(logs.ScanFailed{Reason: err.Error(), TargetHost: in.Host})
		return nil, err
	}
	final, err := h.Producer.Produce(ctx, v)
	if err != nil {
		h.LogFn(ctx).Error(logs.ProduceFailed{Reason: err.Error(), TargetHost: in.Host})
	}
	return final, err
}
