module github.com/facebookincubator/sks

go 1.17

require (
	github.com/aimeemikaelac/certtostore v0.0.0-20190808233848-607c0dfcbe2f
	github.com/facebookincubator/flog v0.0.0-20190930132826-d2511d0ce33c
	github.com/google/go-tpm v0.3.2
	github.com/jgoguen/go-utils v0.0.0-20200211015258-b42ad41486fd
	github.com/peterbourgon/diskv v2.0.1+incompatible
	security/sks v0.0.0-00010101000000-000000000000
)

require (
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/go-ole/go-ole v1.2.5 // indirect
	github.com/google/btree v1.0.0 // indirect
	github.com/google/certtostore v0.0.0-20210722184506-b20658cb17cd // indirect
	github.com/google/logger v1.1.1 // indirect
	golang.org/x/sys v0.0.0-20210426230700-d19ff857e887 // indirect
)

replace security/sks => ../sks
