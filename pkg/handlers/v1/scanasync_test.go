package v1

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"

	domain "github.com/asecurityteam/nmap-scanner/pkg/domain"
	gomock "github.com/golang/mock/gomock"
	"github.com/stretchr/testify/require"
)

func newID() string {
	u, _ := uuid.NewUUID()
	return u.String()
}

func TestScanAsyncFetch(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	s := NewMockStore(ctrl)
	h := &ScanAsyncFetch{Store: s}
	id := newID()
	ctx := context.Background()

	s.EXPECT().Load(ctx, id).Return(nil, domain.InProgressError{Identifier: id})
	out, err := h.Handle(ctx, AsyncScanQuery{Identifier: id})
	require.Nil(t, err)
	require.Equal(t, stateInProgress, out.Status)

	s.EXPECT().Load(ctx, id).Return(nil, domain.NotFoundError{Identifier: id})
	out, err = h.Handle(ctx, AsyncScanQuery{Identifier: id})
	require.Nil(t, err)
	require.Equal(t, stateUnknown, out.Status)

	s.EXPECT().Load(ctx, id).Return(nil, errors.New(""))
	_, err = h.Handle(ctx, AsyncScanQuery{Identifier: id})
	require.NotNil(t, err)

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
	expected := []ScanFinding{
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
	}
	s.EXPECT().Load(ctx, id).Return(found, nil)
	out, err = h.Handle(ctx, AsyncScanQuery{Identifier: id})
	require.Nil(t, err)
	require.Equal(t, stateReady, out.Status)
	require.Equal(t, expected, out.Findings)
}

func TestScanAsyncSubmit(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	p := NewMockProducer(ctrl)
	s := NewMockStore(ctrl)
	u, _ := url.Parse("https://127.0.0.1/results")
	id := newID()
	h := &ScanAsyncSubmit{
		LogFn:    testLogFn,
		Producer: p,
		Store:    s,
		BaseURL:  u,
		IDGenerator: func() string {
			return id
		},
	}
	ctx := context.Background()
	in := ScanInput{Host: "127.0.0.1", Scripts: []string{}, ScriptArgs: []string{}}
	ain := AsyncScanInput{ScanInput: in, Identifier: id}
	expectedErr := errors.New("")

	s.EXPECT().Mark(ctx, id).Return(expectedErr)
	_, err := h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	s.EXPECT().Mark(ctx, id).Return(nil)
	p.EXPECT().Produce(ctx, ain).Return(nil, expectedErr)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	s.EXPECT().Mark(ctx, id).Return(nil)
	p.EXPECT().Produce(ctx, ain).Return(ain, nil)
	out, err := h.Handle(ctx, in)
	require.Nil(t, err)
	require.Equal(t, "https://127.0.0.1/results/"+id, out.(AsyncScanOutput).HREF)
}

func TestScanAsync(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	st := NewMockStore(ctrl)
	s := NewMockScanner(ctrl)
	ss := NewMockScriptedScanner(ctrl)
	p := NewMockProducer(ctrl)
	h := &ScanAsync{
		LogFn:           testLogFn,
		Store:           st,
		Producer:        p,
		Scanner:         s,
		ScriptedScanner: ss,
	}
	ctx := context.Background()
	id := newID()
	in := AsyncScanInput{
		Identifier: id,
		ScanInput: ScanInput{
			Host: "127.0.0.1",
		},
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
	expected := AsyncScanResult{
		Status: stateReady,
		Findings: []ScanFinding{
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
		},
	}
	expectedErr := errors.New("")

	s.EXPECT().Scan(ctx, in.Host).Return(nil, expectedErr)
	_, err := h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	s.EXPECT().Scan(ctx, in.Host).Return(found, nil)
	st.EXPECT().Set(ctx, id, found).Return(expectedErr)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	s.EXPECT().Scan(ctx, in.Host).Return(found, nil)
	st.EXPECT().Set(ctx, id, found).Return(nil)
	p.EXPECT().Produce(ctx, expected).Return(nil, expectedErr)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	s.EXPECT().Scan(ctx, in.Host).Return(found, nil)
	st.EXPECT().Set(ctx, id, found).Return(nil)
	p.EXPECT().Produce(ctx, expected).Return(expected, nil)
	_, err = h.Handle(ctx, in)
	require.Nil(t, err)

	s.EXPECT().Scan(ctx, in.Host).Return(nil, domain.MissingScanTargetError{Target: in.Host})
	st.EXPECT().Set(ctx, id, gomock.Any()).Return(nil)
	p.EXPECT().Produce(ctx, gomock.Any()).Return(AsyncScanResult{}, nil)
	f, err := h.Handle(ctx, in)
	require.Nil(t, err)
	require.Equal(t, AsyncScanResult{}, f)

	scripts := []string{"script1", "script2"}
	args := []string{"arg1=v1", "arg2=v2"}
	in = AsyncScanInput{
		Identifier: id,
		ScanInput: ScanInput{
			Host:       "127.0.0.1",
			Scripts:    scripts,
			ScriptArgs: args,
		},
	}

	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(nil, expectedErr)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(found, nil)
	st.EXPECT().Set(ctx, id, found).Return(expectedErr)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(found, nil)
	st.EXPECT().Set(ctx, id, found).Return(nil)
	p.EXPECT().Produce(ctx, expected).Return(nil, expectedErr)
	_, err = h.Handle(ctx, in)
	require.Equal(t, expectedErr, err)

	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(found, nil)
	st.EXPECT().Set(ctx, id, found).Return(nil)
	p.EXPECT().Produce(ctx, expected).Return(expected, nil)
	_, err = h.Handle(ctx, in)
	require.Nil(t, err)

	ss.EXPECT().ScanWithScripts(ctx, scripts, args, in.Host).Return(nil, domain.MissingScanTargetError{Target: in.Host})
	st.EXPECT().Set(ctx, id, gomock.Any()).Return(nil)
	p.EXPECT().Produce(ctx, gomock.Any()).Return(AsyncScanResult{}, nil)
	f, err = h.Handle(ctx, in)
	require.Nil(t, err)
	require.Equal(t, AsyncScanResult{}, f)
}
