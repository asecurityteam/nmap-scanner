package v1

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func TestScanError(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := NewMockScanner(ctrl)
	ss := NewMockScriptedScanner(ctrl)
	p := NewMockProducer(ctrl)
	h := &Scan{
		Producer:        p,
		Scanner:         s,
		ScriptedScanner: ss,
		LogFn:           testLogFn,
	}
	ctx := context.Background()
	in := ScanInput{
		Host: "127.0.0.1",
	}
	expected := errors.New("")

	s.EXPECT().Scan(ctx, in.Host).Return(nil, expected)
	_, err := h.Handle(ctx, in)
	require.Equal(t, expected, err)

	s.EXPECT().Scan(ctx, in.Host).Return(nil, domain.MissingScanTargetError{Target: in.Host})
	_, err = h.Handle(ctx, in)
	require.Equal(t, domain.NotFoundError{Identifier: in.Host}, err)

	s.EXPECT().Scan(ctx, in.Host).Return(nil, nil)
	p.EXPECT().Produce(ctx, gomock.Any()).Return(nil, expected)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expected, err)

	scripts := []string{"script1", "script2"}
	args := []string{"arg1=v1", "arg2=v2"}
	in = ScanInput{
		Host:       "127.0.0.1",
		Scripts:    scripts,
		ScriptArgs: args,
	}
	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(nil, expected)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expected, err)

	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(nil, domain.MissingScanTargetError{Target: in.Host})
	_, err = h.Handle(ctx, in)
	require.Equal(t, domain.NotFoundError{Identifier: in.Host}, err)

	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(nil, nil)
	p.EXPECT().Produce(ctx, gomock.Any()).Return(nil, expected)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expected, err)
}

func TestScanSuccess(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := NewMockScanner(ctrl)
	ss := NewMockScriptedScanner(ctrl)
	p := NewMockProducer(ctrl)
	h := &Scan{
		Producer:        p,
		Scanner:         s,
		ScriptedScanner: ss,
		LogFn:           testLogFn,
	}
	ctx := context.Background()
	in := ScanInput{
		Host: "127.0.0.1",
	}
	ts := time.Now()
	found := []domain.Finding{
		{
			Timestamp: ts,
			IP:        "127.0.0.1",
			Hostnames: []string{"localhost", "testmachine"},
			Vulnerabilities: []domain.Vulnerability{
				{
					Key:   "CVE-1234",
					Title: "AN EXPLOIT",
					State: domain.VulnStateExploit,
					IDs: []domain.VulnerabilityID{
						{Type: "CVE", Value: "CVE-1234"},
					},
					RiskFactor: domain.RiskFactorHigh,
					Scores: []domain.VulnerabilityScore{
						{Type: "CVSSv2", Value: "10.0"},
					},
					Dates: []domain.VulnerabilityDate{
						{
							Type:  "disclosure",
							Year:  1970,
							Month: 01,
							Day:   01,
						},
					},
					Description:    "A VERY BAD EXPLOIT",
					CheckResults:   []string{"INFO: checked a setting"},
					ExploitResults: []string{"passwords: letmein"},
					ExtraInfo:      []string{"OS: linux"},
					References:     []string{"https://127.0.0.1/exploit-database/cve-1234"},
				},
			},
		},
	}
	expected := ScanOutput{Findings: []ScanFinding{
		{
			Timestamp: ts,
			IP:        "127.0.0.1",
			Hostnames: []string{"localhost", "testmachine"},
			Vulnerabilities: []ScanVulnerability{
				{
					Key:   "CVE-1234",
					Title: "AN EXPLOIT",
					State: domain.VulnStateExploit,
					IDs: []ScanVulnerabilityID{
						{Type: "CVE", Value: "CVE-1234"},
					},
					RiskFactor: domain.RiskFactorHigh,
					Scores: []ScanVulnerabilityScore{
						{Type: "CVSSv2", Value: "10.0"},
					},
					Dates: []ScanVulnerabilityDate{
						{
							Type:  "disclosure",
							Year:  1970,
							Month: 01,
							Day:   01,
						},
					},
					Description:    "A VERY BAD EXPLOIT",
					CheckResults:   []string{"INFO: checked a setting"},
					ExploitResults: []string{"passwords: letmein"},
					ExtraInfo:      []string{"OS: linux"},
					References:     []string{"https://127.0.0.1/exploit-database/cve-1234"},
				},
			},
		},
	}}

	s.EXPECT().Scan(ctx, in.Host).Return(found, nil)
	p.EXPECT().Produce(ctx, expected).Return(expected, nil)
	out, err := h.Handle(ctx, in)
	require.Nil(t, err)
	require.Equal(t, expected, out)

	scripts := []string{"script1", "script2"}
	args := []string{"arg1=v1", "arg2=v2"}
	in = ScanInput{
		Host:       "127.0.0.1",
		Scripts:    scripts,
		ScriptArgs: args,
	}
	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(found, nil)
	p.EXPECT().Produce(ctx, expected).Return(expected, nil)
	out, err = h.Handle(ctx, in)
	require.Nil(t, err)
	require.Equal(t, expected, out)
}
