generate: 
	go generate ./...

build-rebpf: 
	go build -ldflags "-s -w" -o rebpf cmd/rebpf.go 

build: generate build-rebpf

clean:
	rm -f rebpf
	rm -f internal/probe/probe_bpf*.go
	rm -f internal/probe/probe_bpf*.o

run: build
	sudo ./rebpf