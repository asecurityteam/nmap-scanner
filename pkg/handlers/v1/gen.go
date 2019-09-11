package v1

//go:generate mockgen -destination mock_scanner_test.go -package v1 github.com/asecurityteam/nmap-scanner/pkg/domain Scanner
//go:generate mockgen -destination mock_scriptedscanner_test.go -package v1 github.com/asecurityteam/nmap-scanner/pkg/domain ScriptedScanner
//go:generate mockgen -destination mock_producer_test.go -package v1 github.com/asecurityteam/nmap-scanner/pkg/domain Producer
//go:generate mockgen -destination mock_store_test.go -package v1 github.com/asecurityteam/nmap-scanner/pkg/domain Store
