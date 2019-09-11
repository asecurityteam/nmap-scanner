package scanner

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	reflect "reflect"
	"testing"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestNMAPCommandFailure(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cm := NewMockCommandMaker(ctrl)
	cr := NewMockCommandRunner(ctrl)

	n := NewNMAP("yes", []string{"-v"}, []string{"one", "two"}, []string{"k=v"})
	n.CommandMaker = cm
	ctx := context.Background()
	expectedFlags := []interface{}{
		`-sV`,
		`-oX`, `-`,
		`-v`,
		`--script`, `one,two`,
		`--script-args`, `vulns.showall=on,vulscanoutput='{id} | {title} | {product} | {version} | {link}\n',k=v`,
		`127.0.0.1`,
	}
	cm.EXPECT().MakeCommand(ctx, "yes", expectedFlags...).Return(cr)
	cr.EXPECT().RunCommand(gomock.Any(), gomock.Any()).Return(errors.New("failure"))
	_, err := n.Scan(ctx, "127.0.0.1")
	require.NotNil(t, err)
}

func TestNMAPOverrides(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cm := NewMockCommandMaker(ctrl)
	cr := NewMockCommandRunner(ctrl)

	n := NewNMAP("yes", []string{"-v"}, []string{"one", "two"}, []string{"k=v"})
	n.CommandMaker = cm
	ctx := context.Background()
	expectedFlags := []interface{}{
		`-sV`,
		`-oX`, `-`,
		`-v`,
		`--script`, `three,four`,
		`--script-args`, `vulns.showall=on,vulscanoutput='{id} | {title} | {product} | {version} | {link}\n',k2=v2`,
		`127.0.0.1`,
	}
	cm.EXPECT().MakeCommand(ctx, "yes", expectedFlags...).Return(cr)
	cr.EXPECT().RunCommand(gomock.Any(), gomock.Any()).Return(errors.New("failure"))
	_, err := n.ScanWithScripts(ctx, []string{"three", "four"}, []string{"k2=v2"}, "127.0.0.1")
	require.NotNil(t, err)
}

func TestNMAPInvalidXMLOutput(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cm := NewMockCommandMaker(ctrl)
	cr := NewMockCommandRunner(ctrl)

	n := NewNMAP("yes", []string{"-v"}, []string{"one", "two"}, []string{"k=v"})
	n.CommandMaker = cm
	ctx := context.Background()

	expectedFlags := []interface{}{
		`-sV`,
		`-oX`, `-`,
		`-v`,
		`--script`, `one,two`,
		`--script-args`, `vulns.showall=on,vulscanoutput='{id} | {title} | {product} | {version} | {link}\n',k=v`,
		`127.0.0.1`,
	}
	cm.EXPECT().MakeCommand(ctx, "yes", expectedFlags...).Return(cr)
	cr.EXPECT().RunCommand(gomock.Any(), gomock.Any()).Do(func(out io.Writer, err io.Writer) {
		_, _ = out.Write([]byte(`NOTXML`))
	}).Return(nil)
	_, err := n.Scan(ctx, "127.0.0.1")
	require.NotNil(t, err)
}

func TestNMAPMissingHost(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cm := NewMockCommandMaker(ctrl)
	cr := NewMockCommandRunner(ctrl)

	n := NewNMAP("yes", []string{"-v"}, []string{"one", "two"}, []string{"k=v"})
	n.CommandMaker = cm
	ctx := context.Background()

	expectedFlags := []interface{}{
		`-sV`,
		`-oX`, `-`,
		`-v`,
		`--script`, `one,two`,
		`--script-args`, `vulns.showall=on,vulscanoutput='{id} | {title} | {product} | {version} | {link}\n',k=v`,
		`127.0.0.1`,
	}
	cm.EXPECT().MakeCommand(ctx, "yes", expectedFlags...).Return(cr)
	cr.EXPECT().RunCommand(gomock.Any(), gomock.Any()).Do(func(out io.Writer, err io.Writer) {
		_, _ = out.Write([]byte(xmlMissingHost))
	}).Return(nil)
	_, err := n.Scan(ctx, "127.0.0.1")
	require.NotNil(t, err)
	require.IsType(t, domain.MissingScanTargetError{}, err)
}

func TestNMAPSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	cm := NewMockCommandMaker(ctrl)
	cr := NewMockCommandRunner(ctrl)

	n := NewNMAP("yes", []string{"-v"}, []string{"one", "two"}, []string{"k=v"})
	n.CommandMaker = cm
	ctx := context.Background()
	expectedFlags := []interface{}{
		`-sV`,
		`-oX`, `-`,
		`-v`,
		`--script`, `one,two`,
		`--script-args`, `vulns.showall=on,vulscanoutput='{id} | {title} | {product} | {version} | {link}\n',k=v`,
		`127.0.0.1`,
	}
	expectedResults := []domain.Finding{domain.Finding{
		Timestamp: time.Unix(1564488249, 0),
		IP:        "127.0.0.1",
		Hostnames: []string{"nmap.org", "ack.nmap.org"},
		Vulnerabilities: []domain.Vulnerability{
			domain.Vulnerability{
				Key:            "NMAP-1",
				Title:          "Anonymous Diffie-Hellman Key Exchange MitM Vulnerability",
				State:          "NOT VULNERABLE",
				IDs:            []domain.VulnerabilityID{},
				Scores:         []domain.VulnerabilityScore{},
				Dates:          []domain.VulnerabilityDate{},
				CheckResults:   []string{},
				ExploitResults: []string{},
				ExtraInfo:      []string{},
				References:     []string{"https://www.ietf.org/rfc/rfc2246.txt"},
				Source:         "ssl-dh-params",
				Port:           443,
				Protocol:       "tcp",
				Service:        "ssl",
			},
			domain.Vulnerability{
				Key:   "CVE-2015-4000",
				Title: "Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)",
				State: "NOT VULNERABLE",
				IDs: []domain.VulnerabilityID{
					domain.VulnerabilityID{Type: "CVE", Value: "CVE-2015-4000"},
					domain.VulnerabilityID{Type: "OSVDB", Value: "122331"},
				},
				Scores:         []domain.VulnerabilityScore{},
				Dates:          []domain.VulnerabilityDate{},
				CheckResults:   []string{},
				ExploitResults: []string{},
				ExtraInfo:      []string{},
				References: []string{
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000",
					"https://weakdh.org",
					"http://osvdb.org/122331",
				},
				Source:   "ssl-dh-params",
				Port:     443,
				Protocol: "tcp",
				Service:  "ssl",
			},
			domain.Vulnerability{
				Key:            "NMAP-2",
				Title:          "Diffie-Hellman Key Exchange Insufficient Group Strength",
				State:          "NOT VULNERABLE",
				IDs:            []domain.VulnerabilityID{},
				Scores:         []domain.VulnerabilityScore{},
				Dates:          []domain.VulnerabilityDate{},
				CheckResults:   []string{},
				ExploitResults: []string{},
				ExtraInfo:      []string{},
				References: []string{
					"https://weakdh.org",
				},
				Source:   "ssl-dh-params",
				Port:     443,
				Protocol: "tcp",
				Service:  "ssl",
			},
			domain.Vulnerability{
				Key:            "NMAP-3",
				Title:          "Diffie-Hellman Key Exchange Incorrectly Generated Group Parameters",
				State:          "NOT VULNERABLE",
				IDs:            []domain.VulnerabilityID{},
				Scores:         []domain.VulnerabilityScore{},
				Dates:          []domain.VulnerabilityDate{},
				CheckResults:   []string{},
				ExploitResults: []string{},
				ExtraInfo:      []string{},
				References: []string{
					"https://weakdh.org",
					"http://www2.esentire.com/TLSUnjammedWP",
				},
				Source:   "ssl-dh-params",
				Port:     443,
				Protocol: "tcp",
				Service:  "ssl",
			},
			domain.Vulnerability{
				Key:            "NMAP-4",
				Title:          "The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.",
				State:          "NOT VULNERABLE",
				IDs:            []domain.VulnerabilityID{},
				Scores:         []domain.VulnerabilityScore{},
				Dates:          []domain.VulnerabilityDate{},
				CheckResults:   []string{},
				ExploitResults: []string{},
				ExtraInfo:      []string{},
				References: []string{
					"http://www.openssl.org/news/secadv_20140407.txt ",
					"http://cvedetails.com/cve/2014-0160/",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160",
				},
				Source:   "ssl-heartbleed",
				Port:     443,
				Protocol: "tcp",
				Service:  "ssl",
			},
			domain.Vulnerability{
				Key:   "CVE-2014-3566",
				Title: "SSL POODLE information leak",
				State: "NOT VULNERABLE",
				IDs: []domain.VulnerabilityID{
					domain.VulnerabilityID{Type: "CVE", Value: "CVE-2014-3566"},
					domain.VulnerabilityID{Type: "OSVDB", Value: "113251"},
				},
				Scores:         []domain.VulnerabilityScore{},
				Dates:          []domain.VulnerabilityDate{},
				CheckResults:   []string{},
				ExploitResults: []string{},
				ExtraInfo:      []string{},
				References: []string{
					"https://www.openssl.org/~bodo/ssl-poodle.pdf",
					"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566",
					"https://www.imperialviolet.org/2014/10/14/poodle.html",
					"http://osvdb.org/113251",
				},
				Source:   "ssl-poodle",
				Port:     443,
				Protocol: "tcp",
				Service:  "ssl",
			},
			domain.Vulnerability{
				Key:   "TEST",
				Title: "I'm full of edge cases",
				State: "NOT VULNERABLE",
				IDs: []domain.VulnerabilityID{
					domain.VulnerabilityID{Type: "UNKNOWN", Value: "EDGECASE"},
				},
				RiskFactor: "High",
				Scores: []domain.VulnerabilityScore{
					domain.VulnerabilityScore{Type: "CVSS", Value: "10.0"},
					domain.VulnerabilityScore{Type: "UNKNOWN", Value: "10.0"},
				},
				Description:    "A test case",
				CheckResults:   []string{"STRING", "STRING2"},
				ExploitResults: []string{"STRING", "STRING2"},
				ExtraInfo:      []string{"STRING", "STRING2"},
				Dates:          []domain.VulnerabilityDate{},
				References:     []string{},
				Source:         "fake-for-test",
				Port:           443,
				Protocol:       "tcp",
				Service:        "ssl",
			},
		},
	},
	}
	cm.EXPECT().MakeCommand(ctx, "yes", expectedFlags...).Return(cr)
	cr.EXPECT().RunCommand(gomock.Any(), gomock.Any()).Do(func(out io.Writer, err io.Writer) {
		_, _ = out.Write([]byte(xmlOutput))
	}).Return(nil)
	results, err := n.Scan(ctx, "127.0.0.1")
	require.Nil(t, err)
	require.Equal(t, expectedResults, results)
}

func Test_parseVulscan(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []domain.Vulnerability
	}{
		{
			name: "empty",
			raw:  "",
			want: nil,
		},
		{
			name: "no match",
			raw:  "CVE-1234 | A crazy exploit | Internet Browser | <1.2.3 | https://127.0.0.1 | 0\n",
			want: []domain.Vulnerability{
				{
					State:          "NOT VULNERABLE",
					Title:          "CVE-1234",
					Description:    "A crazy exploit",
					ExtraInfo:      []string{"Internet Browser", "<1.2.3"},
					References:     []string{"https://127.0.0.1"},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
				},
			},
		},
		{
			name: "one found",
			raw:  "CVE-1234 | A crazy exploit | Internet Browser | <1.2.3 | https://127.0.0.1 | 1\n",
			want: []domain.Vulnerability{
				{
					State:          "VULNERABLE",
					Title:          "CVE-1234",
					Description:    "A crazy exploit",
					ExtraInfo:      []string{"Internet Browser", "<1.2.3"},
					References:     []string{"https://127.0.0.1"},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
				},
			},
		},
		{
			name: "some found",
			raw:  "CVE-1234 | A crazy exploit | Internet Browser | <1.2.3 | https://127.0.0.1 | 1\nINVALID LINE\nCVE-2345 | A better exploit | Internet Server | >1.2.3 | https://127.0.0.1 | 1\nCVE-3456 | A sad exploit | Internet Device | =1.2.3 | https://127.0.0.1 | 1\n",
			want: []domain.Vulnerability{
				{
					State:          "VULNERABLE",
					Title:          "CVE-1234",
					Description:    "A crazy exploit",
					ExtraInfo:      []string{"Internet Browser", "<1.2.3"},
					References:     []string{"https://127.0.0.1"},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
				},
				{
					State:          "VULNERABLE",
					Title:          "CVE-2345",
					Description:    "A better exploit",
					ExtraInfo:      []string{"Internet Server", ">1.2.3"},
					References:     []string{"https://127.0.0.1"},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
				},
				{
					State:          "VULNERABLE",
					Title:          "CVE-3456",
					Description:    "A sad exploit",
					ExtraInfo:      []string{"Internet Device", "=1.2.3"},
					References:     []string{"https://127.0.0.1"},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseVulscan(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseVulscan() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_parseVulnsLib(t *testing.T) {
	var c nmapContainer
	if err := xml.Unmarshal([]byte(xmlOutput), &c); err != nil {
		t.Fatalf("could not unmarshal sample XML: %v", err)
	}
	tests := []struct {
		name   string
		tables []nmapOutputTable
		want   []domain.Vulnerability
	}{
		{
			name:   "no vuln data",
			tables: c.Hosts[0].Ports[0].Scripts[0].Output,
			want:   []domain.Vulnerability{},
		},
		{
			name:   "data that isn't vuln",
			tables: c.Hosts[0].Ports[0].Scripts[3].Output,
			want:   []domain.Vulnerability{},
		},
		{
			name:   "some vulns",
			tables: c.Hosts[0].Ports[0].Scripts[4].Output,
			want: []domain.Vulnerability{
				{
					Key:   "NMAP-1",
					Title: "Anonymous Diffie-Hellman Key Exchange MitM Vulnerability",
					State: "NOT VULNERABLE",
					References: []string{
						"https://www.ietf.org/rfc/rfc2246.txt",
					},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
					ExtraInfo:      []string{},
				},
				{
					Key:   "CVE-2015-4000",
					Title: "Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)",
					State: "NOT VULNERABLE",
					IDs: []domain.VulnerabilityID{
						{
							Type:  "CVE",
							Value: "CVE-2015-4000",
						},
						{
							Type:  "OSVDB",
							Value: "122331",
						},
					},
					References: []string{
						"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000",
						"https://weakdh.org",
						"http://osvdb.org/122331",
					},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
					ExtraInfo:      []string{},
				},
				{
					Key:   "NMAP-2",
					Title: "Diffie-Hellman Key Exchange Insufficient Group Strength",
					State: "NOT VULNERABLE",
					References: []string{
						"https://weakdh.org",
					},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
					ExtraInfo:      []string{},
				},
				{
					Key:   "NMAP-3",
					Title: "Diffie-Hellman Key Exchange Incorrectly Generated Group Parameters",
					State: "NOT VULNERABLE",
					References: []string{
						"https://weakdh.org",
						"http://www2.esentire.com/TLSUnjammedWP",
					},
					IDs:            []domain.VulnerabilityID{},
					Scores:         []domain.VulnerabilityScore{},
					Dates:          []domain.VulnerabilityDate{},
					CheckResults:   []string{},
					ExploitResults: []string{},
					ExtraInfo:      []string{},
				},
			},
		},
		{
			name:   "extended cases",
			tables: c.Hosts[0].Ports[0].Scripts[7].Output,
			want: []domain.Vulnerability{
				{
					Key:   "TEST",
					Title: "I'm full of edge cases",
					State: "NOT VULNERABLE",
					IDs: []domain.VulnerabilityID{
						{Type: "UNKNOWN", Value: "EDGECASE"},
					},
					RiskFactor:  "High",
					Description: "A test case",
					CheckResults: []string{
						"STRING",
						"STRING2",
					},
					ExploitResults: []string{
						"STRING",
						"STRING2",
					},
					ExtraInfo: []string{
						"STRING",
						"STRING2",
					},
					Scores: []domain.VulnerabilityScore{
						{Type: "CVSS", Value: "10.0"},
						{Type: "UNKNOWN", Value: "10.0"},
					},
					Dates:      []domain.VulnerabilityDate{},
					References: []string{},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseVulnsLib(tt.tables); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseVulnsLib() = %v, want %v", got, tt.want)
			}
		})
	}
}

var xmlOutput = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.70 scan initiated Tue Jul 30 12:03:40 2019 as: nmap -sV -oX - -&#45;script-args vulns.showall -&#45;script &quot;ssl-* and not intrusive&quot; -p 443 nmap.org -->
<nmaprun scanner="nmap" args="nmap -sV -oX - -&#45;script-args vulns.showall -&#45;script &quot;ssl-* and not intrusive&quot; -p 443 nmap.org" start="1564488220" startstr="Tue Jul 30 12:03:40 2019" version="7.70" xmloutputversion="1.04">
    <scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
    <verbose level="0"/>
    <debugging level="0"/>
    <host starttime="1564488221" endtime="1564488249">
        <status state="up" reason="reset" reason_ttl="37"/>
        <address addr="127.0.0.1" addrtype="ipv4"/>
        <hostnames>
            <hostname name="nmap.org" type="user"/>
            <hostname name="ack.nmap.org" type="PTR"/>
        </hostnames>
        <ports>
            <port protocol="tcp" portid="443">
                <state state="open" reason="syn-ack" reason_ttl="37"/>
                <service name="ssl" product="Apache httpd" extrainfo="SSL-only mode" tunnel="ssl" method="probed" conf="10">
                    <cpe>cpe:/a:apache:http_server</cpe>
                </service>
                <script id="http-server-header" output="Apache/2.4.6 (CentOS)">
                    <elem>Apache/2.4.6 (CentOS)</elem>
                </script>
                <script id="ssl-ccs-injection" output="No reply from server (TIMEOUT)"/>
                <script id="ssl-cert" output="Subject: commonName=nmap.org&#xa;Subject Alternative Name: DNS:nmap.org, DNS:www.nmap.org&#xa;Issuer: commonName=COMODO RSA Domain Validation Secure Server CA/organizationName=COMODO CA Limited/stateOrProvinceName=Greater Manchester/countryName=GB&#xa;Public Key type: rsa&#xa;Public Key bits: 2048&#xa;Signature Algorithm: sha256WithRSAEncryption&#xa;Not valid before: 2018-03-16T00:00:00&#xa;Not valid after:  2020-03-15T23:59:59&#xa;MD5:   5599 32bd b525 e603 9fe4 79ae c08f b937&#xa;SHA-1: d002 e880 a3da c739 a061 df50 a69b c9ad 21d1 e5a4">
                    <table key="subject">
                        <elem key="organizationalUnitName">PositiveSSL</elem>
                        <elem key="commonName">nmap.org</elem>
                    </table>
                    <table key="issuer">
                        <elem key="localityName">Salford</elem>
                        <elem key="countryName">GB</elem>
                        <elem key="stateOrProvinceName">Greater Manchester</elem>
                        <elem key="commonName">COMODO RSA Domain Validation Secure Server CA</elem>
                        <elem key="organizationName">COMODO CA Limited</elem>
                    </table>
                    <table key="pubkey">
                        <elem key="bits">2048</elem>
                        <elem key="type">rsa</elem>
                        <elem key="modulus">userdata: 0x56339ea82ce8</elem>
                        <elem key="exponent">userdata: 0x56339ea82b58</elem>
                    </table>
                    <table key="extensions">
                        <table>
                            <elem key="value">keyid:90:AF:6A:3A:94:5A:0B:D8:90:EA:12:56:73:DF:43:B4:3A:28:DA:E7&#xa;</elem>
                            <elem key="name">X509v3 Authority Key Identifier</elem>
                        </table>
                        <table>
                            <elem key="value">23:95:2E:4F:56:E5:E6:D7:BB:A0:58:8B:1E:3D:52:67:FE:DC:D6:3B</elem>
                            <elem key="name">X509v3 Subject Key Identifier</elem>
                        </table>
                        <table>
                            <elem key="value">Digital Signature, Key Encipherment</elem>
                            <elem key="name">X509v3 Key Usage</elem>
                            <elem key="critical">true</elem>
                        </table>
                        <table>
                            <elem key="value">CA:FALSE</elem>
                            <elem key="name">X509v3 Basic Constraints</elem>
                            <elem key="critical">true</elem>
                        </table>
                        <table>
                            <elem key="value">TLS Web Server Authentication, TLS Web Client Authentication</elem>
                            <elem key="name">X509v3 Extended Key Usage</elem>
                        </table>
                        <table>
                            <elem key="value">Policy: 1.3.6.1.4.1.6449.1.2.2.7&#xa;  CPS: https://secure.comodo.com/CPS&#xa;Policy: 2.23.140.1.2.1&#xa;</elem>
                            <elem key="name">X509v3 Certificate Policies</elem>
                        </table>
                        <table>
                            <elem key="value">&#xa;Full Name:&#xa;  URI:http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl&#xa;</elem>
                            <elem key="name">X509v3 CRL Distribution Points</elem>
                        </table>
                        <table>
                            <elem key="value">CA Issuers - URI:http://crt.comodoca.com/COMODORSADomainValidationSecureServerCA.crt&#xa;OCSP - URI:http://ocsp.comodoca.com&#xa;</elem>
                            <elem key="name">Authority Information Access</elem>
                        </table>
                        <table>
                            <elem key="value">DNS:nmap.org, DNS:www.nmap.org</elem>
                            <elem key="name">X509v3 Subject Alternative Name</elem>
                        </table>
                    </table>
                    <elem key="sig_algo">sha256WithRSAEncryption</elem>
                    <table key="validity">
                        <elem key="notAfter">2020-03-15T23:59:59</elem>
                        <elem key="notBefore">2018-03-16T00:00:00</elem>
                    </table>
                    <elem key="md5">559932bdb525e6039fe479aec08fb937</elem>
                    <elem key="sha1">d002e880a3dac739a061df50a69bc9ad21d1e5a4</elem>
                    <elem key="pem">-&#45;&#45;&#45;&#45;BEGIN CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;MIIFPDCCBCSgAwIBAgIQbVQUphIoJZgFlxUyetzKyDANBgkqhkiG9w0BAQsFADCB&#xa;kDELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G&#xa;A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxNjA0BgNV&#xa;BAMTLUNPTU9ETyBSU0EgRG9tYWluIFZhbGlkYXRpb24gU2VjdXJlIFNlcnZlciBD&#xa;QTAeFw0xODAzMTYwMDAwMDBaFw0yMDAzMTUyMzU5NTlaMEwxITAfBgNVBAsTGERv&#xa;bWFpbiBDb250cm9sIFZhbGlkYXRlZDEUMBIGA1UECxMLUG9zaXRpdmVTU0wxETAP&#xa;BgNVBAMTCG5tYXAub3JnMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA&#xa;wh2pqISnf79T0vD7wDzxNbrLu+KcAYSDQjJtGPSqsc9D9l1RL9PK0keKVtZ/PnTX&#xa;Qz99hcVeuFQca1pI50xOGARp30xjWS2mDfCwB+wHUNVzsNNQf80/Vt7GLiURAU0S&#xa;s2JD1tIG5EejY5xhOydDDudBwKkN6UG1H0Qhk3TP2mR2NH8Y9Opf7yzd+FD+OGWB&#xa;DSMs8D4P5dZ2w+jgsv4IhxBmBj/mMCom6rD3H+qoNLb9Lo9tiDuNWgyVlqjyiBrq&#xa;Fs8d+O8Iwmg7NxMGDcwPe8UBhosDWOjOJX0aYbtVazIkhmKx9xsW+kMUvU1E8TVu&#xa;30Ea3tIet4rxFWm04onwcwIDAQABo4IB0zCCAc8wHwYDVR0jBBgwFoAUkK9qOpRa&#xa;C9iQ6hJWc99DtDoo2ucwHQYDVR0OBBYEFCOVLk9W5ebXu6BYix49Umf+3NY7MA4G&#xa;A1UdDwEB/wQEAwIFoDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMB&#xa;BggrBgEFBQcDAjBPBgNVHSAESDBGMDoGCysGAQQBsjEBAgIHMCswKQYIKwYBBQUH&#xa;AgEWHWh0dHBzOi8vc2VjdXJlLmNvbW9kby5jb20vQ1BTMAgGBmeBDAECATBUBgNV&#xa;HR8ETTBLMEmgR6BFhkNodHRwOi8vY3JsLmNvbW9kb2NhLmNvbS9DT01PRE9SU0FE&#xa;b21haW5WYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3JsMIGFBggrBgEFBQcBAQR5&#xa;MHcwTwYIKwYBBQUHMAKGQ2h0dHA6Ly9jcnQuY29tb2RvY2EuY29tL0NPTU9ET1JT&#xa;QURvbWFpblZhbGlkYXRpb25TZWN1cmVTZXJ2ZXJDQS5jcnQwJAYIKwYBBQUHMAGG&#xa;GGh0dHA6Ly9vY3NwLmNvbW9kb2NhLmNvbTAhBgNVHREEGjAYgghubWFwLm9yZ4IM&#xa;d3d3Lm5tYXAub3JnMA0GCSqGSIb3DQEBCwUAA4IBAQA2QPGvonw8VUdY98VbAPwM&#xa;eo24P2zxpzB3TEMrGKng+74DRtqQvPmnxrr+hDgBvxuU1UPyQcx/B5tJb+uNk2uM&#xa;f79+VeINwmgM0GNkwcMAq2qnkGfKeqNwqWNezBSGBwent5fCkjkeEM2Kk39vvkhk&#xa;/6Q/abRTZP7WdSLhjuKfTTyVTCbXRBkBEONxvJPu139GRHMM7E/LRKZa2TbRNNND&#xa;SqoBsOWK0ChDbirlk19x3OPasYkw3O6fheD/GOsTna+WSICuBYv6X4adchkzjwdW&#xa;+JDRV0gheNMV0/KJepvdUOMG5Wb/KqARVDBuFgLYNYH72B3Xnd7bFrw0GRpsrbBg&#xa;-&#45;&#45;&#45;&#45;END CERTIFICATE-&#45;&#45;&#45;&#45;&#xa;</elem>
                </script>
                <script id="ssl-date" output="TLS randomness does not represent time"></script>
                <script id="ssl-dh-params" output="&#xa;  NOT VULNERABLE:&#xa;  Anonymous Diffie-Hellman Key Exchange MitM Vulnerability&#xa;    State: NOT VULNERABLE&#xa;    References:&#xa;      https://www.ietf.org/rfc/rfc2246.txt&#xa;  &#xa;  Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)&#xa;    State: NOT VULNERABLE&#xa;    IDs:  CVE:CVE-2015-4000  OSVDB:122331&#xa;    References:&#xa; https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000&#xa;      https://weakdh.org&#xa;      http://osvdb.org/122331&#xa;  &#xa;  Diffie-Hellman Key Exchange Insufficient Group Strength&#xa;    State: NOT VULNERABLE&#xa;    References:&#xa;      https://weakdh.org&#xa;  &#xa;  Diffie-Hellman Key Exchange Incorrectly Generated Group Parameters&#xa;    State: NOT VULNERABLE&#xa;    References:&#xa;      https://weakdh.org&#xa;      http://www2.esentire.com/TLSUnjammedWP&#xa;">
                    <table key="NMAP-1">
                        <elem key="title">Anonymous Diffie-Hellman Key Exchange MitM Vulnerability</elem>
                        <elem key="state">NOT VULNERABLE</elem>
                        <table key="refs">
                            <elem>https://www.ietf.org/rfc/rfc2246.txt</elem>
                        </table>
                    </table>
                    <table key="CVE-2015-4000">
                        <elem key="title">Transport Layer Security (TLS) Protocol DHE_EXPORT Ciphers Downgrade MitM (Logjam)</elem>
                        <elem key="state">NOT VULNERABLE</elem>
                        <table key="ids">
                            <elem>CVE:CVE-2015-4000</elem>
                            <elem>OSVDB:122331</elem>
                        </table>
                        <table key="refs">
                            <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-4000</elem>
                            <elem>https://weakdh.org</elem>
                            <elem>http://osvdb.org/122331</elem>
                        </table>
                    </table>
                    <table key="NMAP-2">
                        <elem key="title">Diffie-Hellman Key Exchange Insufficient Group Strength</elem>
                        <elem key="state">NOT VULNERABLE</elem>
                        <table key="refs">
                            <elem>https://weakdh.org</elem>
                        </table>
                    </table>
                    <table key="NMAP-3">
                        <elem key="title">Diffie-Hellman Key Exchange Incorrectly Generated Group Parameters</elem>
                        <elem key="state">NOT VULNERABLE</elem>
                        <table key="refs">
                            <elem>https://weakdh.org</elem>
                            <elem>http://www2.esentire.com/TLSUnjammedWP</elem>
                        </table>
                    </table>
                </script>
                <script id="ssl-heartbleed" output="&#xa;  NOT VULNERABLE:&#xa;  The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.&#xa;    State: NOT VULNERABLE&#xa;    References:&#xa;      http://www.openssl.org/news/secadv_20140407.txt &#xa;      http://cvedetails.com/cve/2014-0160/&#xa; https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160&#xa;">
                    <table key="NMAP-4">
                        <elem key="title">The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.</elem>
                        <elem key="state">NOT VULNERABLE</elem>
                        <table key="refs">
                            <elem>http://www.openssl.org/news/secadv_20140407.txt </elem>
                            <elem>http://cvedetails.com/cve/2014-0160/</elem>
                            <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160</elem>
                        </table>
                    </table>
                </script>
                <script id="ssl-poodle" output="&#xa;  NOT VULNERABLE:&#xa;  SSL POODLE information leak&#xa;    State: NOT VULNERABLE&#xa;    IDs:  CVE:CVE-2014-3566  OSVDB:113251&#xa;    References:&#xa;      https://www.openssl.org/~bodo/ssl-poodle.pdf&#xa; https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566&#xa;      https://www.imperialviolet.org/2014/10/14/poodle.html&#xa;      http://osvdb.org/113251&#xa;">
                    <table key="CVE-2014-3566">
                        <elem key="title">SSL POODLE information leak</elem>
                        <elem key="state">NOT VULNERABLE</elem>
                        <table key="ids">
                            <elem>CVE:CVE-2014-3566</elem>
                            <elem>OSVDB:113251</elem>
                        </table>
                        <table key="refs">
                            <elem>https://www.openssl.org/~bodo/ssl-poodle.pdf</elem>
                            <elem>https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566</elem>
                            <elem>https://www.imperialviolet.org/2014/10/14/poodle.html</elem>
                            <elem>http://osvdb.org/113251</elem>
                        </table>
                    </table>
				</script>
				<script id="fake-for-test">
                    <table key="TEST">
                        <elem key="title">I'm full of edge cases</elem>
						<elem key="state">NOT VULNERABLE</elem>
						<elem key="ids">EDGECASE</elem>
						<elem key="risk_factor">High</elem>
						<elem key="description">A test case</elem>
						<elem key="check_results">STRING</elem>
						<elem key="exploit_results">STRING</elem>
						<elem key="extra_info">STRING</elem>
						<table key="check_results">
							<elem>STRING2</elem>
						</table>
						<table key="exploit_results">
							<elem>STRING2</elem>
						</table>
						<table key="extra_info">
							<elem>STRING2</elem>
						</table>
						<table key="scores">
							<elem>CVSS:10.0</elem>
							<elem>10.0</elem>
						</table>
                    </table>
                </script>
            </port>
        </ports>
        <times srtt="7783" rttvar="17779" to="100000"/>
    </host>
    <runstats>
        <finished time="1564488249" timestr="Tue Jul 30 12:04:09 2019" elapsed="28.67" summary="Nmap done at Tue Jul 30 12:04:09 2019; 1 IP address (1 host up) scanned in 28.67 seconds" exit="success"/>
        <hosts up="1" down="0" total="1"/>
    </runstats>
</nmaprun>
`

var xmlMissingHost = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/local/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 7.70 scan initiated Tue Jul 30 12:03:40 2019 as: nmap -sV -oX - -&#45;script-args vulns.showall -&#45;script &quot;ssl-* and not intrusive&quot; -p 443 nmap.org -->
<nmaprun scanner="nmap" args="nmap -sV -oX - -&#45;script-args vulns.showall -&#45;script &quot;ssl-* and not intrusive&quot; -p 443 nmap.org" start="1564488220" startstr="Tue Jul 30 12:03:40 2019" version="7.70" xmloutputversion="1.04">
    <scaninfo type="syn" protocol="tcp" numservices="1" services="443"/>
    <verbose level="0"/>
    <debugging level="0"/>
    <runstats>
        <finished time="1564488249" timestr="Tue Jul 30 12:04:09 2019" elapsed="28.67" summary="Nmap done at Tue Jul 30 12:04:09 2019; 1 IP address (1 host up) scanned in 28.67 seconds" exit="success"/>
        <hosts up="0" down="0" total="0"/>
    </runstats>
</nmaprun>
`

func TestNMAPComponent(t *testing.T) {
	cmp := NewComponent(testLogFn)
	require.Equal(t, "scanner", cmp.Settings().Name())
	s, err := cmp.New(context.Background(), cmp.Settings())
	require.Nil(t, err)
	require.NotNil(t, s)
}
