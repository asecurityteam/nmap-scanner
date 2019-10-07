<a id="markdown-nmap-scanner" name="nmap-scanner"></a>
# nmap-scanner
[![GoDoc](https://godoc.org/github.com/asecurityteam/nmap-scanner?status.svg)](https://godoc.org/github.com/asecurityteam/nmap-scanner)

A collection of custom nmap scripts and a service that executes them against
a host. We use this to run our vulnerability proofs-of-concept against our own
hosts as well as for regular scans of all of our hosts for regressions.

<https://github.com/asecurityteam/nmap-scanner>

<!-- TOC -->

- [nmap-scanner](#nmap-scanner)
    - [Overview](#overview)
    - [Quick Start](#quick-start)
    - [Configuration](#configuration)
        - [Adding Your Own Scripts](#adding-your-own-scripts)
        - [Logging](#logging)
        - [Stats](#stats)
    - [Status](#status)
    - [Contributing](#contributing)
        - [Building And Testing](#building-and-testing)
        - [Quality Gates](#quality-gates)
        - [License](#license)
        - [Contributing Agreement](#contributing-agreement)

<!-- /TOC -->

<a id="markdown-overview" name="overview"></a>
## Overview

Atlassian uses a handful of different vulnerability detection tools and
techniques. However, most commercial solutions don't have a great amount of
flexibility for creating extensions or leveraging a scan engine to do custom
work. To cover this gap we use [nmap](https://nmap.org/) and the `nmap`
scripting engine to enable our analysts to write and run their own scans.

Included with this project are all of the custom scripts we've written (in the
`scripts` directory) and a service that orchestrates the running of those
scripts. The service is included to aid in automating scans.

<a id="markdown-quick-start" name="quick-start"></a>
## Quick Start

Install docker and docker-compose.

The app can be run locally by running `make run`.

This will start a service listening on 8080.

```sh
curl -v \
    --request POST \
    --header "Content-Type:application/json" \
    --data '{"host": "myserver.com"}' \
    "http://localhost:8080"
```

Or to run a scan using a non-default set of scripts:

```sh
curl -v \
    --request POST \
    --header "Content-Type:application/json" \
    --data '{"host": "myserver.com", "scripts": ["http-vuln-*", "ssl-*"]}' \
    "http://localhost:8080"
```

<a id="markdown-configuration" name="configuration"></a>
## Configuration

Images of this project are built, and hosted on
[DockerHub](https://cloud.docker.com/u/asecurityteam/repository/docker/asecurityteam/nmap-scanner).
The system is configured using environment variables. The following are all of
the configuration options for the system:

```bash
# (bool) Use the Lambda SDK to start the system.
NMAPSCANNER_LAMBDAMODE="false"
# (string) Name of the function to host in Lambda mode.
NMAPSCANNER_LAMBDAFUNCTION="scan"
# (string) The base URL path on which results will be available.
NMAPSCANNER_RESULTSURL=""
# ([]string) Any script arguments to inject. Form of argname='argvalue'
NMAPSCANNER_SCANNER_SCRIPTARGS="vulscanoutput='{id} | {title} | {product} | {version} | {link}\n' vulns.showall=on"
# ([]string) Nmap scripts to execute. Paths must be relative to the nmap script root.
NMAPSCANNER_SCANNER_SCRIPTS="http-* ssl-* vulscan/vulscan.nse"
# (string) Nmap binary arguments/flags to pass.
NMAPSCANNER_SCANNER_BINARGS="-T5"
# (string) Nmap binary path to execute.
NMAPSCANNER_SCANNER_BINPATH="nmap"
# (string) The type of data store to use for results tracking.
NMAPSCANNER_STORE_TYPE="MEMORY"
# (string) Name of the TTL key.
NMAPSCANNER_STORE_DYNAMODB_TTLKEY="ttl"
# (string) Name of the table partition key.
NMAPSCANNER_STORE_DYNAMODB_PARTITIONKEY="identity"
# (string) The name of the DynamoDB table to use.
NMAPSCANNER_STORE_DYNAMODB_TABLENAME="ScanResults"
# (string) Override the default AWS URL.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_ENDPOINT=""
# (string) The AWS region in which to authenticate.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_REGION=""
# (string) Name of the profile to use from the file.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_SHAREDPROFILE_PROFILE=""
# (string) The location of the shared profile configuration file. Leave blank for the default AWS location.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_SHAREDPROFILE_FILE=""
# (string) Optional access token.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_STATIC_TOKEN=""
# (string)
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_STATIC_SECRET=""
# (string) The access key ID.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_STATIC_ID=""
# (string) External ID to use if using a cross-acount role.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_ASSUMEROLE_EXTERNALID=""
# (string) The ARN of the role to assume.
NMAPSCANNER_STORE_DYNAMODB_AWS_SESSION_ASSUMEROLE_ROLE=""
# (string)
NMAPSCANNER_RESULTSPRODUCER_TYPE="BENTHOS"
# (string) The YAML or JSON text of a Benthos configuration.
NMAPSCANNER_RESULTSPRODUCER_BENTHOS_YAML=""
# (string) The URL to POST.
NMAPSCANNER_RESULTSPRODUCER_POST_ENDPOINT=""
# (string) The type of HTTP client. Choices are SMART and DEFAULT.
NMAPSCANNER_RESULTSPRODUCER_POST_HTTPCLIENT_TYPE="DEFAULT"
# (string)
NMAPSCANNER_RESULTSPRODUCER_POST_HTTPCLIENT_DEFAULTCONFIG_CONTENTTYPE="application/json"
# (string) The full OpenAPI specification with transportd extensions.
NMAPSCANNER_RESULTSPRODUCER_POST_HTTPCLIENT_SMART_OPENAPI=""
# (string)
NMAPSCANNER_WORKPRODUCER_TYPE="BENTHOS"
# (string) The YAML or JSON text of a Benthos configuration.
NMAPSCANNER_WORKPRODUCER_BENTHOS_YAML=""
# (string) The URL to POST.
NMAPSCANNER_WORKPRODUCER_POST_ENDPOINT=""
# (string) The type of HTTP client. Choices are SMART and DEFAULT.
NMAPSCANNER_WORKPRODUCER_POST_HTTPCLIENT_TYPE="DEFAULT"
# (string)
NMAPSCANNER_WORKPRODUCER_POST_HTTPCLIENT_DEFAULTCONFIG_CONTENTTYPE="application/json"
# (string) The full OpenAPI specification with transportd extensions.
NMAPSCANNER_WORKPRODUCER_POST_HTTPCLIENT_SMART_OPENAPI="

# (string) The listening address of the server.
SERVERFULL_HTTPSERVER_ADDRESS=":8080"
# (time.Duration) Interval on which gauges are reported.
SERVERFULL_CONNSTATE_REPORTINTERVAL="5s"
# (string) Name of the counter metric tracking hijacked clients.
SERVERFULL_CONNSTATE_HIJACKEDCOUNTER="http.server.connstate.hijacked"
# (string) Name of the counter metric tracking closed clients.
SERVERFULL_CONNSTATE_CLOSEDCOUNTER="http.server.connstate.closed"
# (string) Name of the gauge metric tracking idle clients.
SERVERFULL_CONNSTATE_IDLEGAUGE="http.server.connstate.idle.gauge"
# (string) Name of the counter metric tracking idle clients.
SERVERFULL_CONNSTATE_IDLECOUNTER="http.server.connstate.idle"
# (string) Name of the gauge metric tracking active clients.
SERVERFULL_CONNSTATE_ACTIVEGAUGE="http.server.connstate.active.gauge"
# (string) Name of the counter metric tracking active clients.
SERVERFULL_CONNSTATE_ACTIVECOUNTER="http.server.connstate.active"
# (string) Name of the gauge metric tracking new clients.
SERVERFULL_CONNSTATE_NEWGAUGE="http.server.connstate.new.gauge"
# (string) Name of the counter metric tracking new clients.
SERVERFULL_CONNSTATE_NEWCOUNTER="http.server.connstate.new"
# (string) Name of the metric tracking allocated bytes
SERVERFULL_EXPVAR_ALLOC="go_expvar.memstats.alloc"
# (string) Name of the metric tracking number of frees
SERVERFULL_EXPVAR_FREES="go_expvar.memstats.frees"
# (string) Name of the metric tracking allocated bytes
SERVERFULL_EXPVAR_HEAPALLOC="go_expvar.memstats.heap_alloc"
# (string) Name of the metric tracking bytes in unused spans
SERVERFULL_EXPVAR_HEAPIDLE="go_expvar.memstats.heap_idle"
# (string) Name of the metric tracking bytes in in-use spans
SERVERFULL_EXPVAR_HEAPINUSE="go_expvar.memstats.heap_inuse"
# (string) Name of the metric tracking total number of object allocated"
SERVERFULL_EXPVAR_HEAPOBJECT="go_expvar.memstats.heap_objects"
# (string) Name of the metric tracking bytes realeased to the OS
SERVERFULL_EXPVAR_HEAPREALEASED="go_expvar.memstats.heap_released"
# (string) Name of the metric tracking bytes obtained from the system
SERVERFULL_EXPVAR_HEAPSTATS="go_expvar.memstats.heap_sys"
# (string) Name of the metric tracking number of pointer lookups
SERVERFULL_EXPVAR_LOOKUPS="go_expvar.memstats.lookups"
# (string) Name of the metric tracking number of mallocs
SERVERFULL_EXPVAR_MALLOCS="go_expvar.memstats.mallocs"
# (string) Name of the metric tracking number of garbage collections
SERVERFULL_EXPVAR_NUMGC="go_expvar.memstats.num_gc"
# (string) Name of the metric tracking duration of GC pauses
SERVERFULL_EXPVAR_PAUSENS="go_expvar.memstats.pause_ns"
# (string) Name of the metric tracking total GC pause duration over lifetime process
SERVERFULL_EXPVAR_PAUSETOTALNS="go_expvar.memstats.pause_total_ns"
# (string) Name of the metric tracking allocated bytes (even if freed)
SERVERFULL_EXPVAR_TOTALALLOC="go_expvar.memstats.total_alloc"
# (string) Name of the metric tracking number of active go routines
SERVERFULL_EXPVAR_GOROUTINESEXISTS="go_expvar.goroutines.exists"
# (time.Duration) Interval on which metrics are reported
SERVERFULL_EXPVAR_REPORTINTERVAL="5s"
# (string) Destination stream of the logs. One of STDOUT, NULL.
SERVERFULL_LOGGER_OUTPUT="STDOUT"
# (string) The minimum level of logs to emit. One of DEBUG, INFO, WARN, ERROR.
SERVERFULL_LOGGER_LEVEL="INFO"
# (string) Destination stream of the stats. One of NULLSTAT, DATADOG.
SERVERFULL_STATS_OUTPUT="DATADOG"
# (int) Max packet size to send.
SERVERFULL_STATS_DATADOG_PACKETSIZE="32768"
# ([]string) Any static tags for all metrics.
SERVERFULL_STATS_DATADOG_TAGS=""
# (time.Duration) Frequencing of sending metrics to listener.
SERVERFULL_STATS_DATADOG_FLUSHINTERVAL="10s"
# (string) Listener address to use when sending metrics.
SERVERFULL_STATS_DATADOG_ADDRESS="localhost:8125"
# ([]string) Which signal handlers are installed. Choices are OS.
SERVERFULL_SIGNALS_INSTALLED="OS"
# ([]int) Which signals to listen for.
SERVERFULL_SIGNALS_OS_SIGNALS="15 2"
```

<a id="markdown-adding-your-own-scripts" name="adding-your-own-scripts"></a>
### Adding Your Own Scripts

There are a few ways to do this. One option is to fork our repository, add
your scripts to the `scripts` directory, and rebuild the image using the
included Dockerfile. All scripts in the `scripts` directory are copied into the
resulting image and automatically executed when scanning a target. If you have
some scripts you're adding that you think are generally useful then please
consider making a PR.

Another option is to extend our image with a Dockerfile like:

```docker
FROM asecurityteam/nmap-scanner:latest
COPY /path/to/your/custom/scripts/* /usr/local/share/nmap/scripts/custom/
```

This allows you to run the same service we provide through our public docker
image but with your extensions bundled in.

<a id="markdown-logging" name="logging"></a>
### Logging

This project makes use of [logevent](https://github.com/asecurityteam/logevent)
which provides structured logging using Go structs and tags. By default the
project will set a logger value in the context for each request. The handler
uses the `LogFn` function defined in `pkg/domain/alias.go` to extract the logger
instance from the context.

The built in logger can be configured through the serverfull runtime
[configuration](https://github.com/asecurityteam/serverfull#configuration).

<a id="markdown-stats" name="stats"></a>
### Stats

This project uses [xstats](https://github.com/rs/xstats) as its underlying stats
library. By default the project will set a stat client value in the context for
each request. The handler uses the `StatFn` function defined in
`pkg/domain/alias.go` to extract the logger instance from the context.

The built in stats client can be configured through the serverfull runtime
[configuration](https://github.com/asecurityteam/serverfull#configuration).

Additional resources:

* [serverfull](https://github.com/asecurityteam/serverfull)
* [serverfull-gateway](https://github.com/asecurityteam/serverfull-gateway)

<a id="markdown-status" name="status"></a>
## Status

This project is in incubation which means we are not yet operating this tool in
production and the interfaces are subject to change.

<a id="markdown-contributing" name="contributing"></a>
## Contributing

If you are interested in contributing to the project, feel free to open an issue
or PR.

<a id="markdown-building-and-testing" name="building-and-testing"></a>
### Building And Testing

We publish a docker image called [SDCLI](https://github.com/asecurityteam/sdcli)
that bundles all of our build dependencies. It is used by the included Makefile
to help make building and testing a bit easier. The following actions are
available through the Makefile:

-   make dep

    Install the project dependencies into a vendor directory

-   make lint

    Run our static analysis suite

-   make test

    Run unit tests and generate a coverage artifact

-   make integration

    Run integration tests and generate a coverage artifact

-   make coverage

    Report the combined coverage for unit and integration tests

-   make build

    Generate a local build of the project (if applicable)

-   make run

    Run a local instance of the project (if applicable)

-   make doc

    Generate the project code documentation and make it viewable
    locally.

<a id="markdown-quality-gates" name="quality-gates"></a>
### Quality Gates

Our build process will run the following checks before going green:

-   make lint
-   make test
-   make integration
-   make coverage (combined result must be 85% or above for the project)

Running these locally, will give early indicators of pass/fail.

<a id="markdown-license" name="license"></a>
### License

This project is licensed under Apache 2.0. See LICENSE.txt for details.

<a id="markdown-contributing-agreement" name="contributing-agreement"></a>
### Contributing Agreement

Atlassian requires signing a contributor's agreement before we can accept a
patch. If you are an individual you can fill out the
[individual CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=3f94fbdc-2fbe-46ac-b14c-5d152700ae5d).
If you are contributing on behalf of your company then please fill out the
[corporate CLA](https://na2.docusign.net/Member/PowerFormSigning.aspx?PowerFormId=e1c17c66-ca4d-4aab-a953-2c231af4a20b).
