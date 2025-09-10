package packet

import (
	"encoding/binary"
	"net/netip"
	"github.com/gookit/color"
)

type Packet struct {
    SrcIP     netip.Addr
    DstIP     netip.Addr
    SrcPort   uint16
    DstPort   uint16
    Seq       uint32
    AckSeq    uint32
	TcpFlags  uint8
    TimeStamp uint64
}

func UnmarshalBinary(in []byte) (Packet, bool) {
    srcIP, ok := netip.AddrFromSlice(in[0:4])

    if !ok {
        return Packet{}, ok
    }

    dstIP, ok := netip.AddrFromSlice(in[4:8])

    if !ok {
        return Packet{}, ok
    }

    return Packet{
        SrcIP:     srcIP,
        DstIP:     dstIP,
        SrcPort:   binary.BigEndian.Uint16(in[8:10]),
        DstPort:   binary.BigEndian.Uint16(in[10:12]),
        Seq:       binary.BigEndian.Uint32(in[12:16]),
        AckSeq:    binary.BigEndian.Uint32(in[16:20]),
        TcpFlags:  in[20],
        TimeStamp: binary.LittleEndian.Uint64(in[24:32]),
    }, true
}

// func hash(value []byte) uint64 {
// 	hash := fnv.New64a()
// 	hash.Write(value)
// 	return hash.Sum64()
// }

// func (pkt *Packet) Hash() uint64 {
//     data := make([]byte, 20)
// 	tmp := make([]byte, 4)

// 	data = append(data, pkt.SrcIP.AsSlice()...)  
// 	binary.BigEndian.PutUint16(tmp[:2], pkt.SrcPort)
// 	data = append(data, tmp[:2]...)
	
// 	data = append(data, pkt.DstIP.AsSlice()...)  
// 	binary.BigEndian.PutUint16(tmp[:2], pkt.DstPort)
// 	data = append(data, tmp[:2]...)

// 	binary.BigEndian.PutUint32(tmp, pkt.Seq)
// 	data = append(data, tmp...)
// 	binary.BigEndian.PutUint32(tmp, pkt.AckSeq)
// 	data = append(data, tmp...)

//     return hash(data)
// }

func PrintPacketInfo(pkt Packet, packetType int) {

	if(packetType == 0){
		colorCyan("src: %v:%-7v\tdst: %v:%-9v\tSeq: %-4v\tAckSeq: %-4v\n",
				pkt.SrcIP.Unmap().String(),
				pkt.SrcPort,
				pkt.DstIP.Unmap().String(),
				pkt.DstPort,
				pkt.Seq,
				pkt.AckSeq,
		)
	} else {
		colorLightYellow("src: %v:%-7v\tdst: %v:%-9v\tSeq: %-4v\tAckSeq: %-4v\n",
				pkt.SrcIP.Unmap().String(),
				pkt.SrcPort,
				pkt.DstIP.Unmap().String(),
				pkt.DstPort,
				pkt.Seq,
				pkt.AckSeq,
		)
	}
	
}

var (
    colorLightYellow = color.LightYellow.Printf
    colorCyan        = color.Cyan.Printf
)