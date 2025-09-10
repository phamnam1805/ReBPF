//go:build linux

package probe

import (
	"context"
	"log"
	"net"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"ReBPF/internal/packet"
)

//go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/rebpf.bpf.c -- -O2

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

type probe struct {
	bpfObjects *probeObjects
	tcpRetransmitLink      link.Link
	tcpTransmitLink      link.Link
}

func htons(hostOrder uint16) uint16 {
    return (hostOrder << 8) | (hostOrder >> 8)
}

func htonl(hostOrder uint32) uint32 {
    return ((hostOrder & 0xFF) << 24) |
           (((hostOrder >> 8) & 0xFF) << 16) |
           (((hostOrder >> 16) & 0xFF) << 8) |
           ((hostOrder >> 24) & 0xFF)
}

func parseIPv4ToBe32(ipStr string) (uint32, error) {
    ip := net.ParseIP(ipStr)
    if ip == nil {
        return 0, fmt.Errorf("invalid IP address: %s", ipStr)
    }
    
    ipv4 := ip.To4()
    if ipv4 == nil {
        return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
    }
    
	return uint32(ipv4[0])<<24 | uint32(ipv4[1])<<16 | uint32(ipv4[2])<<8 | uint32(ipv4[3]), nil
}

func setRlimit() error {
     log.Println("Setting rlimit")

     return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
         Cur: twentyMegaBytes,
         Max: fortyMegaBytes,
     })
}

func (p *probe) loadObjects() error {
	log.Printf("Loading probe object into kernel")

	objs := probeObjects{}

	if err := loadProbeObjects(&objs, nil); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) attachPrograms() error {
	log.Printf("Attaching bpf programs to kernel")

	tcpRetransmitLink, err := link.AttachTracing(link.TracingOptions{
        Program: p.bpfObjects.FentryTcpRetransmitSkb,
    })
    if err != nil {
        log.Printf("Failed to attach fentry/tcp_retransmit_skb: %v", err)
        return err
    }
    p.tcpRetransmitLink = tcpRetransmitLink

	log.Printf("Successfully attached to fentry/tcp_retransmit_skb")

    tcpTransmitLink, err := link.AttachTracing(link.TracingOptions{
        Program: p.bpfObjects.FentryTcpTransmitSkb,
    })
	if err != nil {
        log.Printf("Failed to attach fentry/__tcp_transmit_skb: %v", err)
        return err
    }
    p.tcpTransmitLink = tcpTransmitLink

	log.Printf("Successfully attached to fentry/__tcp_transmit_skb")

	targetIP := "172.17.0.2"    // Change to your target IP
    targetPort := 5201          // Change to your target port
    
	matchIp, err := parseIPv4ToBe32(targetIP)
	if err != nil {
        log.Printf("Failed to parse Ipv4: %v", err)
        return err
    }
	err = p.bpfObjects.probeVariables.MatchIp.Set(matchIp)   
	if err != nil {
		log.Printf("Failed to Set variable %v", err)
	}

	err = p.bpfObjects.probeVariables.MatchPort.Set(htons(uint16(targetPort)))   
	if err != nil {
		log.Printf("Failed to Set variable %v", err)
	}

	return nil
}

func newProbe() (*probe, error) {
	log.Println("Creating a new probe")

	prbe := probe{}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.attachPrograms(); err != nil {
		log.Printf("Failed attaching bpf programs: %v", err)
		return nil, err
	}

	return &prbe, nil
}


func (p *probe) Close() error {
	log.Println("Closing eBPF object")
	
	if p.tcpRetransmitLink != nil {
        p.tcpRetransmitLink.Close()
    }

	if p.tcpTransmitLink != nil {
        p.tcpTransmitLink.Close()
    }

	if err := p.bpfObjects.Close(); err != nil {
		log.Println("Failed closing eBPF object")
		return err
	}

	return nil
}

func Run(ctx context.Context) error {
	log.Println("Starting up the probe")

	if err := setRlimit(); err != nil {
		log.Printf("Failed setting rlimit: %v", err)
		return err
	}

	probe, err := newProbe()

	if err != nil {
		return err
	}
	
	retransmitPipe := probe.bpfObjects.probeMaps.RetransmitPipe

	retransmitReader, err := ringbuf.NewReader(retransmitPipe)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer retransmitReader.Close()

	transmitPipe := probe.bpfObjects.probeMaps.TransmitPipe

	transmitReader, err := ringbuf.NewReader(transmitPipe)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer transmitReader.Close()

	retransmitCount := 0

	go func() {

        for {

            event, err := retransmitReader.Read()
            if err != nil {
                if ctx.Err() != nil {
                    return 
                }
                log.Printf("Failed reading from retransmit ringbuf: %v", err)
                continue
            }

            retransmitCount++
            packetAttrs, ok := packet.UnmarshalBinary(event.RawSample)
            if !ok {
                log.Printf("Could not unmarshall retransmit packet: %+v", event.RawSample)
                continue
            }
            packet.PrintPacketInfo(packetAttrs, 0)
			// _ = packetAttrs
        }
    }()

    
	transmitCount := 0

	go func() {
        for {
            event, err := transmitReader.Read()
            if err != nil {
                if ctx.Err() != nil {
                    return 
                }
                log.Printf("Failed reading from transmit ringbuf: %v", err)
                continue
            }

            transmitCount++
            
			packetAttrs, ok := packet.UnmarshalBinary(event.RawSample)
			if !ok {
				log.Printf("Could not unmarshall transmit packet: %+v", event.RawSample)
				continue
			}
			// packet.PrintPacketInfo(packetAttrs, 1)
			_ = packetAttrs
        }
    }()

	<-ctx.Done()
    log.Println("Context cancelled, shutting down...")
	log.Printf("Retransmit goroutine stopped. Total: %d", retransmitCount)
	log.Printf("Transmit goroutine stopped. Total: %d", transmitCount)
    return probe.Close()
}