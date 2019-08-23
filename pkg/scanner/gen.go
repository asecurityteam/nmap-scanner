package scanner

//go:generate mockgen -destination mock_commandmaker_test.go -package scanner github.com/asecurityteam/nmap-scanner/pkg/scanner CommandMaker
//go:generate mockgen -destination mock_commandrunner_test.go -package scanner github.com/asecurityteam/nmap-scanner/pkg/scanner CommandRunner
