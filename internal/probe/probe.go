//go:build linux

package probe

import (
	"context"
	"log"
	"net"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"ReBPF/internal/packet"
	"ReBPF/clsact"
)

//go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/rebpf.bpf.c -- -O2

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

type probe struct {
	iface netlink.Link
	handle     *netlink.Handle
	qdisc      *clsact.ClsAct
	filters    []*netlink.BpfFilter
	bpfObjects *probeObjects
	fentryTcpRetransmitLink      link.Link
	fexitTcpRetransmitLink      link.Link
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

	if err := loadProbeObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions {
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) createQdisc() error {
	log.Printf("Creating clsact qdisc")

	p.qdisc = clsact.NewClsAct(&netlink.QdiscAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	})

	if err := p.handle.QdiscAdd(p.qdisc); err != nil {
		if err := p.handle.QdiscReplace(p.qdisc); err != nil {
			return err
		}
	}

	return nil
}

func (p *probe) createFilters() error {
	log.Printf("Creating qdisc ingress/egress filters")

	addFilter := func(attrs netlink.FilterAttrs) {
		p.filters = append(p.filters, &netlink.BpfFilter{
			FilterAttrs:  attrs,
			Fd:           p.bpfObjects.probePrograms.RedirectToLoopback.FD(),
			DirectAction: true,
		})
	}

	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_INGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	addFilter(netlink.FilterAttrs{
		LinkIndex: p.iface.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_MIN_EGRESS,
		Protocol:  unix.ETH_P_IP,
	})

	// addFilter(netlink.FilterAttrs{
	// 	LinkIndex: p.iface.Attrs().Index,
	// 	Handle:    netlink.MakeHandle(0xffff, 0),
	// 	Parent:    netlink.HANDLE_MIN_INGRESS,
	// 	Protocol:  unix.ETH_P_IPV6,
	// })

	// addFilter(netlink.FilterAttrs{
	// 	LinkIndex: p.iface.Attrs().Index,
	// 	Handle:    netlink.MakeHandle(0xffff, 0),
	// 	Parent:    netlink.HANDLE_MIN_EGRESS,
	// 	Protocol:  unix.ETH_P_IPV6,
	// })

	for _, filter := range p.filters {
		if err := p.handle.FilterAdd(filter); err != nil {
			if err := p.handle.FilterReplace(filter); err != nil {
				return err
			}
		}
	}

	return nil
}



func (p *probe) attachPrograms() error {
	log.Printf("Attaching bpf programs to kernel")
	

	fentryTcpRetransmitLink, err := link.AttachTracing(link.TracingOptions{
        Program: p.bpfObjects.FentryTcpRetransmitSkb,
    })
    if err != nil {
        log.Printf("Failed to attach fentry/tcp_retransmit_skb: %v", err)
        return err
    }
    p.fentryTcpRetransmitLink = fentryTcpRetransmitLink

	log.Printf("Successfully attached to fentry/tcp_retransmit_skb")

	fexitTcpRetransmitLink, err := link.AttachTracing(link.TracingOptions{
        Program: p.bpfObjects.FexitTcpRetransmitSkb,
    })
    if err != nil {
        log.Printf("Failed to attach fexit/tcp_retransmit_skb: %v", err)
        return err
    }
    p.fexitTcpRetransmitLink = fexitTcpRetransmitLink

	log.Printf("Successfully attached to fexit/tcp_retransmit_skb")

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

func newProbe(iface netlink.Link) (*probe, error) {
	log.Println("Creating a new probe")

	handle, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	if err != nil {
		log.Printf("Failed getting netlink handle: %v", err)
		return nil, err
	}


	prbe := probe{
		iface:  iface,
		handle: handle,
	}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.createQdisc(); err != nil {
		log.Printf("Failed creating qdisc: %v", err)
		return nil, err
	}

	if err := prbe.createFilters(); err != nil {
		log.Printf("Failed creating qdisc filters: %v", err)
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
	
	if p.fentryTcpRetransmitLink != nil {
        p.fentryTcpRetransmitLink.Close()
    }

	if p.fexitTcpRetransmitLink != nil {
        p.fexitTcpRetransmitLink.Close()
    }

	log.Println("Removing qdisc")
	if err := p.handle.QdiscDel(p.qdisc); err != nil {
		log.Println("Failed deleting qdisc")
		return err
	}

	log.Println("Removing qdisc filters")

	for _, filter := range p.filters {
		if err := p.handle.FilterDel(filter); err != nil {
			log.Println("Failed deleting qdisc filters")
			return err
		}
	}

	log.Println("Deleting handle")
	p.handle.Delete()

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

	iface, err := netlink.LinkByName("docker0")
	if err != nil {
		log.Printf("Failed linking iface by name: %v", err)
	}

	probe, err := newProbe(iface)
	if err != nil {
		log.Printf("Failed creating new probe: %v", err)
	}
	
	retransmitPipe := probe.bpfObjects.probeMaps.RetransmitPipe

	retransmitReader, err := ringbuf.NewReader(retransmitPipe)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer retransmitReader.Close()

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

	<-ctx.Done()
    log.Println("Context cancelled, shutting down...")
	log.Printf("Retransmit goroutine stopped. Total: %d", retransmitCount)
    return probe.Close()
}