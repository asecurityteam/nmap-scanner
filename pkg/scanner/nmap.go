package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os/exec"
	"strings"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
)

// ScriptsDiscoverer is an interface internal to the NMAP implementation of
// domain.Scanner that is responsible for loading all of the available
// custom scripts to run.
type ScriptsDiscoverer interface {
	DiscoverScripts() ([]string, error)
}

// DirectoryScriptsDiscoverer inspects a given directory path for scripts to
// execute.
type DirectoryScriptsDiscoverer struct {
	Directory string
	// RelativePath is the value that will be prefixed to the script name
	// in order to tell nmap where the script resides within the internal,
	// nmap script directory. For example, if the Directory value is
	// ${NAMP_SCRIPTS_DIR}/custom then this value should be /custom
	RelativePath string
}

// DiscoverScripts reports all files from the given directory.
func (d *DirectoryScriptsDiscoverer) DiscoverScripts() ([]string, error) {
	scriptFiles, err := ioutil.ReadDir(d.Directory)
	if err != nil {
		return nil, err
	}
	results := make([]string, 0, len(scriptFiles))
	for _, scriptFile := range scriptFiles {
		results = append(results, d.RelativePath+scriptFile.Name())
	}
	return results, nil
}

type outputElement struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type outputTable struct {
	Elements []outputElement `xml:"elem"`
}

type script struct {
	ID        string        `xml:"id,attr"`
	RawOutput string        `xml:"output,attr"`
	Output    []outputTable `xml:"table"`
}

type portState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type portService struct {
	Name      string `xml:"name,attr"`
	Product   string `xml:"product,attr"`
	ExtraInfo string `xml:"extrainfo,attr"`
	Method    string `xml:"method,attr"`
}

type port struct {
	Protocol      string      `xml:"protocol,attr"`
	ID            int         `xml:"portid,attr"`
	PortState     portState   `xml:"state"`
	PortServerice portService `xml:"service"`
	Scripts       []script    `xml:"script"`
}

type address struct {
	IP   string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type hostName struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type host struct {
	StartTime int        `xml:"starttime,attr"`
	EndTime   int        `xml:"endtime,attr"`
	Address   address    `xml:"address"`
	HostNames []hostName `xml:"hostnames>hostname"`
	Ports     []port     `xml:"ports>port"`
}

type nmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []host   `xml:"host"`
}

type report struct {
	ID             string
	Description    string
	Product        string
	ProductVersion string
	Link           string
}

// NMAP implements the scanner interface by making a subprocess call to nmap.
type NMAP struct {
	ScriptsDiscoverer ScriptsDiscoverer
}

// Scan a host using nmap.
func (s *NMAP) Scan(ctx context.Context, host string) (domain.Finding, error) {
	scripts, err := s.ScriptsDiscoverer.DiscoverScripts()
	if err != nil {
		return domain.Finding{}, err
	}
	scriptString := &strings.Builder{}
	_, _ = scriptString.WriteString("--script=vulscan/vulscan.nse")
	for _, script := range scripts {
		_, _ = scriptString.WriteString(",")
		_, _ = scriptString.WriteString(script)
	}
	cmd := exec.CommandContext(
		ctx,
		"nmap",
		`-sV`,
		`-oX`, `-`,
		scriptString.String(),
		`--script-args`, `vulscanoutput='{id} | {title} | {product} | {version} | {link}\n'`,
		host,
	)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return domain.Finding{}, fmt.Errorf(
			"nmap failed: stdout(%s) || stderr(%s)",
			stdout.String(), stderr.String(),
		)
	}
	r := nmapRun{}
	if err := xml.Unmarshal(stdout.Bytes(), &r); err != nil {
		return domain.Finding{}, fmt.Errorf("failed to unmarshal nmap output: %v", err)
	}
	if len(r.Hosts) < 1 {
		return domain.Finding{}, domain.MissingScanTargetError{Target: host}
	}
	// We only scan one host so there should be at-most one host entry.
	// TODO: report cases of multiple hosts and/or determine how to handle them.
	h := r.Hosts[0]
	hnames := make([]string, 0, len(h.HostNames))
	for _, hname := range h.HostNames {
		hnames = append(hnames, hname.Name)
	}
	f := domain.Finding{
		Timestamp: time.Unix(int64(h.EndTime), 0),
		IP:        h.Address.IP,
		Hostnames: hnames,
	}
	for _, port := range h.Ports {
		if len(port.Scripts) < 1 {
			continue // Skip entries with no detected vulns
		}
		for _, script := range port.Scripts {
			var reports []report
			var err error
			switch {
			case strings.EqualFold(script.ID, "vulscan"):
				// This is a special case where we can't, yet, conform the
				// output of vulscan to our expected format.
				// TODO: Either make a PR to vulscan that supports structured
				// output or write our own version of it.
				reports, err = parseVulscan(script.RawOutput)
			default:
				// Assume all other scripts conform to our output standard.
				reports, err = parseScript(script.Output)
			}
			if err != nil {
				return domain.Finding{}, fmt.Errorf(
					"failed to parse nmap output: %v", err,
				)
			}
			for _, rep := range reports {
				f.Vulnerabilities = append(f.Vulnerabilities, domain.Vulnerability{
					ID:             rep.ID,
					Description:    rep.Description,
					Product:        rep.Product,
					ProductVersion: rep.ProductVersion,
					Link:           rep.Link,
					Source:         script.ID,
					Port:           port.ID,
					Protocol:       port.Protocol,
					Service:        port.PortServerice.Name,
				})
			}
		}
	}
	return f, nil
}

func parseVulscan(raw string) ([]report, error) {
	s := bufio.NewScanner(strings.NewReader(raw))
	var r []report
	for s.Scan() {
		parts := strings.Split(s.Text(), "|")
		if len(parts) != 5 {
			continue // there are various other lines in there that aren't results
		}
		r = append(r, report{
			ID:             strings.TrimSpace(parts[0]),
			Description:    strings.TrimSpace(parts[1]),
			Product:        strings.TrimSpace(parts[2]),
			ProductVersion: strings.TrimSpace(parts[3]),
			Link:           strings.TrimSpace(parts[4]),
		})
	}
	return r, nil
}

func parseScript(tables []outputTable) ([]report, error) {
	var r []report
	for _, table := range tables {
		var rp report
		for _, element := range table.Elements {
			switch {
			case strings.EqualFold(element.Key, "id"):
				rp.ID = element.Value
			case strings.EqualFold(element.Key, "description"):
				rp.Description = element.Value
			case strings.EqualFold(element.Key, "product"):
				rp.Product = element.Value
			case strings.EqualFold(element.Key, "productVersion"):
				rp.ProductVersion = element.Value
			case strings.EqualFold(element.Key, "link"):
				rp.Link = element.Value
			}
		}
		r = append(r, rp)
	}
	return r, nil
}
