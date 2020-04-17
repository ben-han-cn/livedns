package packet

import (
	"fmt"
	"net"
	"time"
)

type PktMeta struct {
	CapTime time.Time
}

type PktDirection int

const (
	Unknown PktDirection = 0
	Input   PktDirection = 1
	Output  PktDirection = 2
)

func (direction PktDirection) String() string {
	switch direction {
	case Input:
		return "in"
	case Output:
		return "out"
	default:
		return "unknown"
	}
}

type Packet struct {
	Direction PktDirection
	SrcPort   uint16
	DstPort   uint16

	SrcIP   net.IP
	DstIP   net.IP
	Payload []byte
	Meta    *PktMeta
}

func (pkt *Packet) String() string {
	return fmt.Sprintf("%s %s:%d  %s:%d", pkt.Direction.String(), pkt.SrcIP.String(), pkt.SrcPort, pkt.DstIP.String(), pkt.DstPort)
}

type PktSource interface {
	PktChan() <-chan Packet
	StartPump(fiter string) error
	Stop()
}
