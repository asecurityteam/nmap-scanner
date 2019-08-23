package v1

import (
	"context"
	"net/url"
	"path"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/asecurityteam/nmap-scanner/pkg/logs"
)

const (
	stateInProgress = "IN_PROGRESS"
	stateReady      = "READY"
	stateError      = "ERROR"
	stateUnknown    = "UNKNOWN"
)

// AsyncScanQuery is the container for a scan to check on.
type AsyncScanQuery struct {
	Identifier string `json:"id"`
}

// AsyncScanResult is the response to a query.
type AsyncScanResult struct {
	Status   string        `json:"status"`
	Findings []ScanFinding `json:"findings,omitempty"`
}

// ScanAsyncFetch is activated when attempting to retrieve the results.
type ScanAsyncFetch struct {
	Store domain.Store
}

// Handle queries for the results of the async ID.
func (h *ScanAsyncFetch) Handle(ctx context.Context, in AsyncScanQuery) (AsyncScanResult, error) {
	r, err := h.Store.Load(ctx, in.Identifier)
	switch err.(type) {
	case nil:
		v := fromDomain(r)
		return AsyncScanResult{
			Status:   stateReady,
			Findings: v,
		}, nil
	case domain.InProgressError:
		return AsyncScanResult{
			Status: stateInProgress,
		}, nil
	case domain.NotFoundError:
		return AsyncScanResult{
			Status: stateUnknown,
		}, nil
	default:
		return AsyncScanResult{
			Status: stateError,
		}, err
	}
}

// AsyncScanInput is a wrapper around ScanInput that adds a tracking ID.
type AsyncScanInput struct {
	ScanInput
	Identifier string `json:"id"`
}

// AsyncScanOutput is the response containing a tracking ID.
type AsyncScanOutput struct {
	Identifier string `json:"id"`
	HREF       string `json:"href"`
}

// ScanAsync manages processing async reuquests.
type ScanAsync struct {
	LogFn    domain.LogFn
	Store    domain.Store
	Scanner  domain.Scanner
	Producer domain.Producer
}

// Handle process the async job.
func (h *ScanAsync) Handle(ctx context.Context, in AsyncScanInput) (interface{}, error) {
	findings, err := h.Scanner.Scan(ctx, in.Host)
	if err != nil {
		h.LogFn(ctx).Error(logs.ScanFailed{Reason: err.Error(), TargetHost: in.Host})
		return nil, err
	}
	if err = h.Store.Set(ctx, in.Identifier, findings); err != nil {
		h.LogFn(ctx).Error(logs.StoreFailed{Reason: err.Error(), TargetHost: in.Host})
		return nil, err
	}
	final, err := h.Producer.Produce(ctx, fromDomain(findings))
	if err != nil {
		h.LogFn(ctx).Error(logs.ProduceFailed{Reason: err.Error(), TargetHost: in.Host})
	}
	return final, err
}

// ScanAsyncSubmit handles pushing scan requests onto some queue or stream for
// later processing
type ScanAsyncSubmit struct {
	LogFn       domain.LogFn
	Producer    domain.Producer
	Store       domain.Store
	BaseURL     *url.URL
	IDGenerator func() string
}

// Handle submits the request to a queue and returns a result href.
func (h *ScanAsyncSubmit) Handle(ctx context.Context, in ScanInput) (interface{}, error) {
	id := h.IDGenerator()
	ain := AsyncScanInput{
		ScanInput:  in,
		Identifier: id,
	}
	if err := h.Store.Mark(ctx, id); err != nil {
		h.LogFn(ctx).Error(logs.MarkFailed{Reason: err.Error()})
		return nil, err
	}
	if _, err := h.Producer.Produce(ctx, ain); err != nil {
		h.LogFn(ctx).Error(logs.EnqueueFailed{Reason: err.Error(), TargetHost: in.Host})
		return nil, err
	}
	p, _ := url.Parse(h.BaseURL.String())
	p.Path = path.Join(p.Path, id)
	return AsyncScanOutput{
		Identifier: id,
		HREF:       p.String(),
	}, nil
}
