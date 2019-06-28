package v1

import (
	"context"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
)

// ScanInput is a container for the JSON request body.
type ScanInput struct {
	Host string `json:"host"`
}

// ScanVulnerability is a JSON compatible version domain.Vulnerability.
type ScanVulnerability struct {
	ID             string `json:"id"`
	Description    string `json:"description"`
	Product        string `json:"product"`
	ProductVersion string `json:"productVersion"`
	Link           string `json:"link"`
	Source         string `json:"source"`
	Port           int    `json:"port"`
	Protocol       string `json:"protocol"`
	Service        string `json:"service"`
}

// ScanFinding is a JSON compatible version of domain.Finding
type ScanFinding struct {
	Timestamp       time.Time           `json:"timestamp"`
	IP              string              `json:"ip"`
	Hostnames       []string            `json:"hostnames"`
	Vulnerabilities []ScanVulnerability `json:"vulnerabilities"`
}

func fromDomain(f domain.Finding) ScanFinding {
	sv := make([]ScanVulnerability, 0, len(f.Vulnerabilities))
	for _, vuln := range f.Vulnerabilities {
		sv = append(sv, ScanVulnerability(vuln))
	}
	return ScanFinding{
		Timestamp:       f.Timestamp,
		IP:              f.IP,
		Hostnames:       f.Hostnames,
		Vulnerabilities: sv,
	}
}

func toDomain(f ScanFinding) domain.Finding {
	sv := make([]domain.Vulnerability, 0, len(f.Vulnerabilities))
	for _, vuln := range f.Vulnerabilities {
		sv = append(sv, domain.Vulnerability(vuln))
	}
	return domain.Finding{
		Timestamp:       f.Timestamp,
		IP:              f.IP,
		Hostnames:       f.Hostnames,
		Vulnerabilities: sv,
	}
}

// Scan is a handler that manages scanning a host on-deman.
type Scan struct {
	Scanner  domain.Scanner
	Producer domain.Producer
}

func (h *Scan) handle(ctx context.Context, in ScanInput) (ScanFinding, error) {
	finding, err := h.Scanner.Scan(ctx, in.Host)
	if err != nil {
		return ScanFinding{}, err
	}
	return fromDomain(finding), nil
}

// Handle is invoked on each request.
func (h *Scan) Handle(ctx context.Context, in ScanInput) (interface{}, error) {
	v, err := h.handle(ctx, in)
	if err != nil {
		return ScanFinding{}, err
	}
	return h.Producer.Produce(ctx, v)
}
