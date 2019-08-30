package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
)

// nmapOutputElement is a key/value pair from a script.
type nmapOutputElement struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// nmapOutputTable is a series of key/value pairs that were emitted by a script.
type nmapOutputTable struct {
	Key      string              `xml:"key,attr"`
	Elements []nmapOutputElement `xml:"elem"`
	Tables   []nmapOutputTable   `xml:"table"`
}

// nmapScript is the container used to parse data from script output.
type nmapScript struct {
	// ID is the name of the script that produced the output. Note that this
	// does not match the same value as passed to --script.
	// Ex: vulscan/vulscan.nse has an ID value of vulscan.
	ID string `xml:"id,attr"`
	// RawOutput is any unstructured data emitted by the script. This enables
	// for custom parsing to be performed on non-compliant scripts.
	RawOutput string `xml:"output,attr"`
	// Output contains any structured output from a script that was emitted
	// using the stdnse.output_table() helper.
	Output []nmapOutputTable `xml:"table"`
}

// nmapPortState is the container used to parse data about the state of a port
// during the scan.
type nmapPortState struct {
	// State is ex: open or closed
	State string `xml:"state,attr"`
	// Reason is the signal that set the state. Ex: syn-ack
	Reason string `xml:"reason,attr"`
}

// nmapPortService is the container used to parse data about the service
// listening on a given port.
type nmapPortService struct {
	// Name is categorical value of the service. Ex: http or tls/https
	Name string `xml:"name,attr"`
	// Product is the detected application listening on the port.
	Product string `xml:"product,attr"`
}

// nmapPort is the container used to parse port scanning results.
type nmapPort struct {
	// Protocol is the friendly name of the network protocol used in the scan.
	// Ex: tcp
	Protocol string `xml:"protocol,attr"`
	// ID is the numeric port number that was scanned.
	ID            int             `xml:"portid,attr"`
	PortState     nmapPortState   `xml:"state"`
	PortServerice nmapPortService `xml:"service"`
	// Scripts each contain the output of a script that ran and detected
	// something.
	Scripts []nmapScript `xml:"script"`
}

// nmapAddress is the container used to parse the scanned IP address.
type nmapAddress struct {
	// IP is the string representation of the IP address scanned.
	IP string `xml:"addr,attr"`
	// Type is ipv4 or ipv6.
	Type string `xml:"addrtype,attr"`
}

// nmapHostName is the container used to parse the final hostnames detected by
// the scanner.
type nmapHostName struct {
	// Name is the actual hostname. Ex: example.com
	Name string `xml:"name,attr"`
	// Type is the kind of name record used. Ex: PTR for reverse DNS pointer
	// records.
	Type string `xml:"type,attr"`
}

// nmapHost is the container used to parse host scan data from the XML nmap
// output.
type nmapHost struct {
	// StarTime of the scan.
	StartTime int `xml:"starttime,attr"`
	// EndTime of the scan. For most purposes, this is used as the "timestamp"
	// of the scan. The weak rationale for this is that the end time represents
	// a time at which all detected vulnerabilities were present as opposed to
	// the start time at which no vulnerabilities were known to be present.
	EndTime   int            `xml:"endtime,attr"`
	Address   nmapAddress    `xml:"address"`
	HostNames []nmapHostName `xml:"hostnames>hostname"`
	// Ports contains the details of all scans as scans are performed for each
	// open port on the host.
	Ports []nmapPort `xml:"ports>port"`
}

// nmapContainer is the top level structure for parsing the XML nmap output.
type nmapContainer struct {
	XMLName xml.Name `xml:"nmaprun"`
	// Hosts contains all of the relevant data from the output. Other data not
	// part of hosts include metadata about the scan that we don't currently
	// need or use.
	Hosts []nmapHost `xml:"host"`
}

// NMAP implements the scanner interface by making a subprocess call to nmap.
type NMAP struct {
	CommandStrings []string
	CommandMaker   CommandMaker
}

// NewNMAP generates a Scanner implementation tha leverages NMAP internally.
func NewNMAP(binPath string, scripts []string, scriptArgs []string) *NMAP {
	strs := []string{
		binPath,
		`-sV`,      // Enable version detection of systems.
		`-oX`, `-`, // Enable XML output mode and send to stdout.
		`--script`, strings.Join(scripts, ","), // Configure enabled scripts,
	}
	if len(scriptArgs) > 0 {
		// Optionally pass in script args if present.
		strs = append(strs, `--script-args`)
		strs = append(strs, strings.Join(scriptArgs, ","))
	}
	return &NMAP{
		CommandStrings: strs,
		CommandMaker:   &ExecMaker{},
	}
}

// Scan a host using nmap.
func (s *NMAP) Scan(ctx context.Context, host string) ([]domain.Finding, error) {
	cmdStr := make([]string, len(s.CommandStrings)+1)
	copy(cmdStr, s.CommandStrings)
	cmdStr[len(cmdStr)-1] = host
	cmd := s.CommandMaker.MakeCommand(ctx, cmdStr[0], cmdStr[1:]...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if err := cmd.RunCommand(&stdout, &stderr); err != nil {
		return nil, fmt.Errorf(
			"nmap failed: stdout(%s) || stderr(%s)",
			stdout.String(), stderr.String(),
		)
	}
	r := nmapContainer{}
	if err := xml.Unmarshal(stdout.Bytes(), &r); err != nil {
		return nil, fmt.Errorf("failed to unmarshal nmap output: %v", err)
	}
	if len(r.Hosts) < 1 {
		return nil, domain.MissingScanTargetError{Target: host}
	}
	fs := make([]domain.Finding, 0, len(r.Hosts))
	for _, h := range r.Hosts {
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
				var reports []domain.Vulnerability
				switch {
				case strings.EqualFold(script.ID, "vulscan"):
					// This is a special case where we can't, yet, conform the
					// output of vulscan to our expected format. Eventually, we
					// either make a PR to vulscan that supports structured
					// output or write our own version of it.
					reports = parseVulscan(script.RawOutput)
				default:
					// Assume all other scripts conform to the vulns module.
					reports = parseVulnsLib(script.Output)
				}
				for offset := range reports {
					reports[offset].Port = port.ID
					reports[offset].Protocol = port.Protocol
					reports[offset].Service = port.PortServerice.Name
					reports[offset].Source = script.ID
					f.Vulnerabilities = append(f.Vulnerabilities, reports[offset])
				}
			}
		}
		fs = append(fs, f)
	}

	return fs, nil
}

func parseVulnsLib(tables []nmapOutputTable) []domain.Vulnerability { //nolint(gocyclo)
	vs := make([]domain.Vulnerability, 0, len(tables))
	for _, tbl := range tables {
		v := domain.Vulnerability{
			Key: tbl.Key,
		}
		for _, elm := range tbl.Elements {
			switch elm.Key {
			case "title":
				v.Title = elm.Value
			case "state":
				v.State = elm.Value
			case "ids":
				parts := strings.Split(elm.Value, ":")
				switch len(parts) {
				case 1:
					v.IDs = append(v.IDs, domain.VulnerabilityID{
						Type:  "UNKNOWN",
						Value: parts[0],
					})
				case 2:
					v.IDs = append(v.IDs, domain.VulnerabilityID{
						Type:  parts[0],
						Value: parts[1],
					})
				default:
				}
			case "risk_factor":
				v.RiskFactor = elm.Value
			case "description":
				v.Description = elm.Value
			case "check_results":
				v.CheckResults = append(v.CheckResults, elm.Value)
			case "exploit_results":
				v.ExploitResults = append(v.ExploitResults, elm.Value)
			case "extra_info":
				v.ExtraInfo = append(v.ExtraInfo, elm.Value)
			}
		}
		if v.Title == "" || v.State == "" {
			continue // invalid vuln
		}
		for _, subtbl := range tbl.Tables {
			switch subtbl.Key {
			case "ids":
				for _, idelm := range subtbl.Elements {
					parts := strings.Split(idelm.Value, ":")
					switch len(parts) {
					case 1:
						v.IDs = append(v.IDs, domain.VulnerabilityID{
							Type:  "UNKNOWN",
							Value: parts[0],
						})
					case 2:
						v.IDs = append(v.IDs, domain.VulnerabilityID{
							Type:  parts[0],
							Value: parts[1],
						})
					default:
					}
				}
			case "check_results":
				for _, elem := range subtbl.Elements {
					v.CheckResults = append(v.CheckResults, elem.Value)
				}
			case "exploit_results":
				for _, elem := range subtbl.Elements {
					v.ExploitResults = append(v.ExploitResults, elem.Value)
				}
			case "extra_info":
				for _, elem := range subtbl.Elements {
					v.ExtraInfo = append(v.ExtraInfo, elem.Value)
				}
			case "refs":
				for _, refelm := range subtbl.Elements {
					v.References = append(v.References, refelm.Value)
				}
			case "scores":
				for _, scorelm := range subtbl.Elements {
					parts := strings.Split(scorelm.Value, ":")
					switch len(parts) {
					case 1:
						v.Scores = append(v.Scores, domain.VulnerabilityScore{
							Type:  "UNKNOWN",
							Value: parts[0],
						})
					case 2:
						v.Scores = append(v.Scores, domain.VulnerabilityScore{
							Type:  parts[0],
							Value: parts[1],
						})
					default:
					}
				}
				// TODO: dates parsing. can't find examples of this output.
			}
		}
		vs = append(vs, v)
	}
	return vs
}

func parseVulscan(raw string) []domain.Vulnerability {
	s := bufio.NewScanner(strings.NewReader(raw))
	var r []domain.Vulnerability // nolint(unknown length, can't preallocate)
	for s.Scan() {
		parts := strings.Split(s.Text(), "|")
		if len(parts) != 5 {
			continue // there are various other lines in there that aren't results
		}
		r = append(r, domain.Vulnerability{
			State:       "VULNERABLE",
			Title:       strings.TrimSpace(parts[0]),
			Description: strings.TrimSpace(parts[1]),
			ExtraInfo: []string{
				strings.TrimSpace(parts[2]),
				strings.TrimSpace(parts[3]),
			},
			References: []string{strings.TrimSpace(parts[4])},
		})
	}
	return r
}

// Config contains options for the Scanner.
type Config struct {
	BinPath    string   `description:"Nmap binary path to execute."`
	Scripts    []string `description:"Nmap scripts to execute. Paths must be relative to the nmap script root."`
	ScriptArgs []string `description:"Any script arguments to inject. Form of argname='argvalue'"`
}

// Name of the configuration root.
func (*Config) Name() string {
	return "scanner"
}

// Component loads a Scanner.
type Component struct{}

// NewComponent populates the defaults.
func NewComponent() *Component {
	return &Component{}
}

// Settings generates the default settings.
func (*Component) Settings() *Config {
	return &Config{
		BinPath: "nmap",
		Scripts: []string{
			"http-*",
			"ssl-*",
			"vulscan/vulscan.nse",
		},
		ScriptArgs: []string{
			`vulscanoutput='{id} | {title} | {product} | {version} | {link}\n'`,
			`vulns.showall=on`,
		},
	}
}

// New constructs a scanner.
func (*Component) New(ctx context.Context, conf *Config) (domain.Scanner, error) {
	return NewNMAP(conf.BinPath, conf.Scripts, conf.ScriptArgs), nil
}
