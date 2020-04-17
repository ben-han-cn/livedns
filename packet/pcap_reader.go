package packet

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PcapReader struct {
	handle    *pcap.Handle
	ifaceAddr net.HardwareAddr
	pktChan   chan Packet
	stopChan  chan struct{}
}

const MaxPktLen = 4096

var _ PktSource = &PcapReader{}

func NewIfaceReader(device string, promisc bool) (*PcapReader, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	deviceIsValid := false
	var ifaceAddr net.HardwareAddr
	for _, iface := range ifaces {
		if iface.Name == device {
			deviceIsValid = true
			ifaceAddr = iface.HardwareAddr
			break
		}
	}

	if deviceIsValid == false {
		return nil, fmt.Errorf("invalid device name")
	}

	handle, err := pcap.OpenLive(device, MaxPktLen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, err
	}

	return &PcapReader{
		handle:    handle,
		ifaceAddr: ifaceAddr,
		pktChan:   make(chan Packet),
		stopChan:  make(chan struct{}),
	}, nil
}

func NewPcapFileReader(fileName string) (*PcapReader, error) {
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return nil, err
	}

	return &PcapReader{
		handle:  handle,
		pktChan: make(chan Packet),
	}, nil
}

func (r *PcapReader) StartPump(filter string) error {
	if err := r.handle.SetBPFFilter(filter); err != nil {
		return err
	}

	go func() {
		pktCh := gopacket.NewPacketSource(r.handle, r.handle.LinkType()).Packets()
		for {
			select {
			case pkt := <-pktCh:
				r.handleNewPacket(pkt)
			case <-r.stopChan:
				return
			}
		}
	}()
	return nil
}

func (r *PcapReader) handleNewPacket(pkt gopacket.Packet) {
	var direction PktDirection
	if r.ifaceAddr != nil {
		linkLayer := pkt.Layer(layers.LayerTypeEthernet)
		if linkLayer == nil {
			return
		}

		if bytes.Equal(linkLayer.(*layers.Ethernet).DstMAC, r.ifaceAddr) {
			direction = Input
		} else {
			direction = Output
		}
	}

	ipLayer := pkt.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ipv4 := ipLayer.(*layers.IPv4)
	srcIP := ipv4.SrcIP
	dstIP := ipv4.DstIP

	udpLayer := pkt.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return
	}

	udp := udpLayer.(*layers.UDP)
	r.pktChan <- Packet{
		Direction: direction,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   uint16(udp.SrcPort),
		DstPort:   uint16(udp.DstPort),
		Payload:   udp.Payload,
		Meta:      &PktMeta{CapTime: pkt.Metadata().Timestamp},
	}
}

func (r *PcapReader) PktChan() <-chan Packet {
	return r.pktChan
}

func (r *PcapReader) Stop() {
	r.stopChan <- struct{}{}
	close(r.pktChan)
	r.handle.Close()
}
