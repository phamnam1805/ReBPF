# ReBPF - eBPF TCP Retransmission Monitor & Drop Analyzer

An advanced eBPF-based tool that hooks into kernel TCP retransmission events to analyze packet drop behavior and correlate retransmission outcomes with Traffic Control (TC) filtering decisions.

## Overview

ReBPF implements a sophisticated three-point hooking system using eBPF to monitor and analyze TCP packet retransmissions. The program tracks packet identifiers at retransmission entry, attempts selective dropping via Traffic Control, and captures the actual retransmission results to determine how TC drop decisions affect kernel return codes.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Kernel Space                                   │
│                                                                             │
│  ┌─────────────────────┐    ┌──────────────────┐    ┌─────────────────────┐ │
│  │fentry/              │    │       TC         │    │fexit/               │ │
│  │tcp_retransmit_skb   │    │   (Egress)       │    │tcp_retransmit_skb   │ │
│  │                     │    │                  │    │                     │ │
│  │1. Capture packet ID │───▶│2. Find packet &  │───▶│3. Get return value  │ │
│  │   & identifiers     │    │   decide:        │    │   from kernel func  │ │
│  │                     │    │   TC_ACT_OK or   │    │                     │ │
│  │                     │    │   TC_ACT_SHOT    │    │                     │ │
│  └─────────────────────┘    └──────────────────┘    └─────────────────────┘ │
│             │                         │                         │           │
└─────────────┼─────────────────────────┼─────────────────────────┼───────────┘
              │                         │                         │
              │                         │                         │
      ┌───────────────────────────────────────────────────────────────────────┐
      │                         Ring Buffer                                   │
      │                    (retransmit events)                                │
      └───────────────────────────────────────────────────────────────────────┘
                                       │
                                       ▼
              ┌─────────────────────────────────────────────────────────────┐
              │                    Userspace                                │
              │                  Go Application                             │
              │                                                             │
              │  • Read ring buffer events                                  │
              │  • Correlate fentry/fexit data                              │
              │  • Print TC drop decision impact on return codes            │
              └─────────────────────────────────────────────────────────────┘
```

### Key Components

- **fentry/tcp_retransmit_skb**: Captures packet identifiers before retransmission attempt
- **TC (Traffic Control)**: Searches for target packets and makes drop/pass decisions
- **fexit/tcp_retransmit_skb**: Retrieves the actual return value from the kernel function
- **Ring Buffer**: High-performance communication channel for event data
- **Go Userspace**: Correlates events and analyzes the impact of TC decisions on return codes

## Features

- ✅ **Three-point hooking system** - fentry/tcp_retransmit_skb, TC, fexit/tcp_retransmit_skb
- ✅ **Packet identification tracking** - Records packet identifiers at retransmission entry
- ✅ **Traffic Control integration** - Finds and selectively drops packets at TC layer
- ✅ **Return code analysis** - Correlates TC drop decisions with kernel function return values
- ✅ **Ring buffer communication** - Efficient kernel-to-userspace event streaming
- ✅ **Real-time monitoring** - Live analysis of retransmission behavior and drop impacts

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

The program monitors TCP retransmissions and correlates TC drop decisions with kernel return codes. When running, you'll see output showing:

- Packet identifiers captured at fentry/tcp_retransmit_skb
- TC drop decisions (TC_ACT_OK or TC_ACT_SHOT)
- Corresponding return codes from fexit/tcp_retransmit_skb
- Analysis of how TC drops affect retransmission outcomes

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

```bash
# Terminal 1: Start ReBPF
sudo ./rebpf

# Terminal 2: Generate traffic with packet loss to trigger retransmissions
iperf3 -s -p 5201 &

# Add network conditions to force retransmissions
sudo tc qdisc add dev lo root netem loss 2% delay 100ms

# Generate TCP traffic
iperf3 -c 127.0.0.1 -p 5201 -t 30
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

### Three-Point Hooking Strategy

1. **fentry/tcp_retransmit_skb**: Records packet identification information before retransmission
2. **TC (Traffic Control)**: Intercepts packets and makes drop/pass decisions (TC_ACT_OK vs TC_ACT_SHOT)
3. **fexit/tcp_retransmit_skb**: Captures the actual return value from the kernel function

### Data Flow

1. **Entry Hook**: When `tcp_retransmit_skb` is called, the fentry hook captures packet identifiers
2. **TC Processing**: Traffic Control layer searches for the identified packet and decides whether to drop it
3. **Exit Hook**: The fexit hook retrieves the return value from `tcp_retransmit_skb`
4. **Event Correlation**: Ring buffer events are sent to userspace for analysis
5. **Result Analysis**: Go application correlates the TC decision with the actual kernel return code

### Drop Decision Analysis

The program reveals the relationship between:
- **TC Drop Actions**: When TC returns `TC_ACT_SHOT` (drop) vs `TC_ACT_OK` (pass)
- **Kernel Return Codes**: The actual return value from `tcp_retransmit_skb` 
- **Retransmission Outcomes**: Understanding how TC drops affect the retransmission process

## Performance

- **Low overhead monitoring**: eBPF hooks operate with minimal performance impact
- **Efficient event correlation**: Ring buffers enable fast fentry/fexit event matching
- **Real-time analysis**: Immediate correlation of TC decisions with kernel return codes
- **Selective targeting**: Focuses only on retransmission events, reducing noise

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
- Inspired by modern network observability and kernel analysis tools
- Thanks to the eBPF community for excellent documentation and examples