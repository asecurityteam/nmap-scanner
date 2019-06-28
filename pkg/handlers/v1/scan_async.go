package v1

import (
	"context"
	"net/url"
	"path"

	"github.com/asecurityteam/nmap-scanner/pkg/domain"
	"github.com/asecurityteam/nmap-scanner/pkg/logs"
	"github.com/google/uuid"
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
	Status  string       `json:"status"`
	Finding *ScanFinding `json:"finding,omitempty"`
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
			Status:  stateReady,
			Finding: &v,
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
	LogFn domain.LogFn
	Store domain.Store
	Scan  *Scan
}

// Handle process the async job.
func (h *ScanAsync) Handle(ctx context.Context, in AsyncScanInput) (interface{}, error) {
	v, err := h.Scan.handle(ctx, in.ScanInput)
	if err != nil {
		return nil, err
	}
	if err = h.Store.Set(ctx, in.Identifier, toDomain(v)); err != nil {
		return nil, err
	}
	return v, nil
}

// ScanAsyncSubmit handles pushing scan requests onto some queue or stream for
// later processing
type ScanAsyncSubmit struct {
	LogFn    domain.LogFn
	Producer domain.Producer
	Store    domain.Store
	BaseURL  *url.URL
}

// Handle submits the request to a queue and returns a result href.
func (h *ScanAsyncSubmit) Handle(ctx context.Context, in ScanInput) (interface{}, error) {
	id, _ := uuid.NewUUID()
	ain := AsyncScanInput{
		ScanInput:  in,
		Identifier: id.String(),
	}
	_, err := h.Producer.Produce(ctx, ain)
	if err != nil {
		return nil, err
	}
	if err = h.Store.Mark(ctx, id.String()); err != nil {
		h.LogFn(ctx).Error(logs.MarkFailed{Reason: err.Error()})
	}
	p, _ := url.Parse(h.BaseURL.String())
	p.Path = path.Join(p.Path, id.String())
	return AsyncScanOutput{
		Identifier: id.String(),
		HREF:       p.String(),
	}, nil
}
