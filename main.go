package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"

	"github.com/google/uuid"

	producer "github.com/asecurityteam/component-producer"
	v1 "github.com/asecurityteam/nmap-scanner/pkg/handlers/v1"
	"github.com/asecurityteam/nmap-scanner/pkg/scanner"
	"github.com/asecurityteam/nmap-scanner/pkg/store"
	"github.com/asecurityteam/runhttp"
	"github.com/asecurityteam/serverfull"
	"github.com/asecurityteam/settings"
)

type resultsConfig struct {
	*producer.Config
}

func (*resultsConfig) Name() string {
	return "resultsproducer"
}

type workConfig struct {
	*producer.Config
}

func (*workConfig) Name() string {
	return "workproducer"
}

type config struct {
	Scanner         *scanner.Config
	Store           *store.Config
	ResultsProducer *resultsConfig
	WorkProducer    *workConfig
	ResultsURL      string `description:"The base URL path on which results will be available."`
	LambdaMode      bool   `description:"Use the Lambda SDK to start the system."`
	LambdaFunction  string `description:"Name of the function to host in Lambda mode."`
}

func (*config) Name() string {
	return "nmapscanner"
}

type component struct {
	Scanner         *scanner.Component
	Store           *store.Component
	ResultsProducer *producer.Component
	WorkProducer    *producer.Component
}

func newComponent() *component {
	return &component{
		Scanner:         scanner.NewComponent(runhttp.LoggerFromContext),
		Store:           store.NewComponent(),
		ResultsProducer: producer.NewComponent(),
		WorkProducer:    producer.NewComponent(),
	}
}

func (c *component) Settings() *config {
	return &config{
		Scanner:         c.Scanner.Settings(),
		Store:           c.Store.Settings(),
		WorkProducer:    &workConfig{c.WorkProducer.Settings()},
		ResultsProducer: &resultsConfig{c.ResultsProducer.Settings()},
	}
}

func (c *component) New(ctx context.Context, conf *config) (func(context.Context, settings.Source) error, error) {
	rp, err := c.ResultsProducer.New(ctx, conf.ResultsProducer.Config)
	if err != nil {
		return nil, err
	}
	wp, err := c.WorkProducer.New(ctx, conf.WorkProducer.Config)
	if err != nil {
		return nil, err
	}
	s, err := c.Store.New(ctx, conf.Store)
	if err != nil {
		return nil, err
	}
	sc, err := c.Scanner.New(ctx, conf.Scanner)
	if err != nil {
		return nil, err
	}
	scanHandler := &v1.Scan{
		LogFn:           runhttp.LoggerFromContext,
		Producer:        rp,
		Scanner:         sc,
		ScriptedScanner: sc,
	}
	asyncScanHandler := &v1.ScanAsync{
		LogFn:           runhttp.LoggerFromContext,
		Store:           s,
		Producer:        rp,
		Scanner:         sc,
		ScriptedScanner: sc,
	}
	u, err := url.Parse(conf.ResultsURL)
	if err != nil {
		return nil, err
	}
	asyncScheduleHandler := &v1.ScanAsyncSubmit{
		LogFn:    runhttp.LoggerFromContext,
		Producer: wp,
		Store:    s,
		BaseURL:  u,
		IDGenerator: func() string {
			u, _ := uuid.NewUUID()
			return u.String()
		},
	}
	asyncResultsHandler := &v1.ScanAsyncFetch{
		Store: s,
	}
	handlers := map[string]serverfull.Function{
		"scan":      serverfull.NewFunction(scanHandler.Handle),
		"scanAsync": serverfull.NewFunction(asyncScanHandler.Handle),
		"schedule":  serverfull.NewFunction(asyncScheduleHandler.Handle),
		"results":   serverfull.NewFunction(asyncResultsHandler.Handle),
	}
	fetcher := &serverfull.StaticFetcher{Functions: handlers}
	if conf.LambdaMode {
		return func(ctx context.Context, source settings.Source) error {
			return serverfull.StartLambda(ctx, source, fetcher, conf.LambdaFunction)
		}, nil
	}
	return func(ctx context.Context, source settings.Source) error {
		return serverfull.StartHTTP(ctx, source, fetcher)
	}, nil
}

func main() {
	source, err := settings.NewEnvSource(os.Environ())
	if err != nil {
		panic(err.Error())
	}
	ctx := context.Background()
	runner := new(func(context.Context, settings.Source) error)
	cmp := newComponent()

	fs := flag.NewFlagSet("nmap-scanner", flag.ContinueOnError)
	fs.Usage = func() {}
	if err = fs.Parse(os.Args[1:]); err == flag.ErrHelp {
		g, _ := settings.GroupFromComponent(cmp)
		fmt.Println("Usage: ")
		fmt.Println(settings.ExampleEnvGroups([]settings.Group{g}))
		return
	}
	err = settings.NewComponent(ctx, source, cmp, runner)
	if err != nil {
		panic(err.Error())
	}
	if err := (*runner)(ctx, source); err != nil {
		panic(err.Error())
	}
}
