# ReBPF - eBPF TCP Packet Monitor

A high-performance network monitoring tool that uses eBPF to hook into kernel TCP transmission and retransmission events, providing real-time packet analysis and filtering capabilities.

## Overview

ReBPF leverages eBPF (Extended Berkeley Packet Filter) technology to monitor TCP traffic at the kernel level without adding significant overhead. The tool hooks into critical TCP kernel functions to capture both normal transmissions and retransmissions, then streams the data to userspace for analysis.

## Architecture

```
┌───────────────────────────┐    ┌──────────────────┐    ┌─────────────────────┐
│   Kernel Space            │    │    Ring Buffer   │    │   Userspace         │
│                           │    │                  │    │                     │
│ fentry/tcp_transmit_skb   │───▶│  transmit_pipe   │───▶│  Go Application     │
│ fentry/tcp_retransmit_skb │───▶│ retransmit_pipe  │───▶│  (probe.go)         │
│                           │    │                  │    │                     │
└───────────────────────────┘    └──────────────────┘    └─────────────────────┘
```

### Key Components

- **eBPF Programs**: Hook into `fentry/tcp_transmit_skb` and `fentry/tcp_retransmit_skb`
- **Ring Buffers**: High-performance kernel-to-userspace data transfer
- **Go Userspace**: Real-time packet processing and filtering
- **Configurable Filters**: Target specific IPs and ports

## Features

- ✅ **Real-time TCP monitoring** with minimal overhead
- ✅ **Separate tracking** of transmissions vs retransmissions  
- ✅ **Configurable filtering** by IP address and port
- ✅ **High-performance** ring buffer communication
- ✅ **Detailed packet information** including sequence numbers, flags, timestamps
- ✅ **Graceful shutdown** with proper resource cleanup

## Prerequisites

- Linux kernel 5.8+ with eBPF support
- Go 1.19+
- `clang` and `llvm` for eBPF compilation
- Root privileges (required for eBPF program loading)

## Installation & Build

### 1. Generate eBPF bytecode
```bash
make generate
```

### 2. Build the Go application
```bash
make build-rebpf
```

## Usage

### Basic Usage
```bash
sudo ./rebpf
```

### Configuration

To customize packet filtering, edit the filter settings in `internal/probe/probe.go`:

```go
func (p *probe) attachPrograms() error {
    // Configure target IP and port
    targetIP := "172.17.0.2"    // Change to your target IP
    targetPort := 5201          // Change to your target port
    
    matchIp, err := parseIPv4ToBe32(targetIP)
    if err != nil {
        return err
    }
    
    err = p.bpfObjects.probeVariables.MatchIp.Set(matchIp)
    err = p.bpfObjects.probeVariables.MatchPort.Set(htons(uint16(targetPort)))
    
    return nil
}
```

## Project Structure

```
ReBPF/
├── bpf/
│   ├── rebpf.bpf.c          # eBPF kernel programs
│   └── common.h             # Shared structures and definitions
├── internal/
│   ├── probe/
│   │   └── probe.go         # Main userspace logic
│   └── packet/
│       └── packet.go        # Packet parsing and formatting
├── scripts/
│   └── netem.sh             # Network emulation scripts for testing
├── Makefile                 # Build automation
└── README.md
```

## Development

### Testing with Traffic Generation

Generate test traffic using iperf3:
```bash
# Terminal 1: Start ReBPF
sudo ./rebpf

# Terminal 2: Generate TCP traffic
iperf3 -s -p 5201 &
iperf3 -c 127.0.0.1 -p 5201 -t 10
```

### Simulate Packet Loss
```bash
# Add packet loss to trigger retransmissions
sudo tc qdisc add dev lo root netem loss 1%

# Clean up
sudo tc qdisc del dev lo root
```

### Debugging

Check if eBPF programs are loaded:
```bash
sudo bpftool prog list | grep tcp
```

View kernel logs:
```bash
sudo dmesg | tail -10
```

## How It Works

### eBPF Hooks

1. **fentry/tcp_transmit_skb**: Captures all outgoing TCP packets
2. **fentry/tcp_retransmit_skb**: Captures TCP retransmission events

### Data Flow

1. eBPF programs filter packets based on configured IP/port
2. Matching packets are serialized and sent via ring buffer
3. Go userspace reads from ring buffer using separate goroutines  
4. Packet information is parsed and displayed in real-time

### Filtering

The tool supports filtering by:
- **Destination IP address**: Target specific hosts
- **Destination port**: Monitor specific services
- **Protocol**: Currently focuses on TCP traffic

## Performance

- **Minimal overhead**: eBPF runs in kernel space with near-zero latency
- **High throughput**: Ring buffers provide efficient data transfer
- **Scalable**: Can handle high-volume traffic scenarios

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly 
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Troubleshooting

### Common Issues

**Permission Denied**
```bash
# Ensure you're running with root privileges
sudo ./rebpf
```

**eBPF Program Load Failed**
```bash
# Check kernel version and eBPF support
uname -r
ls /sys/kernel/debug/tracing/events/syscalls/
```

**No Packets Captured**
```bash
# Verify network activity and filter configuration
sudo netstat -tuln | grep 5201
```

## Acknowledgments

- Built with [cilium/ebpf](https://github.com/cilium/ebpf) Go library
- Inspired by modern network observability tools
- Thanks to the eBPF community for excellent