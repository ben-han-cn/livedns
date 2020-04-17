package packet

import (
	"log"

	"github.com/ben-han-cn/g53"
	"github.com/ben-han-cn/g53/util"
)

type DNSMessageHandler interface {
	HandleMsg(pkt Packet, msg *g53.Message)
}

func RunDNSMessagePump(source PktSource, handler DNSMessageHandler) error {
	if err := source.StartPump("udp and port 53"); err != nil {
		return err
	}

	for pkt := range source.PktChan() {
		msg, err := g53.MessageFromWire(util.NewInputBuffer(pkt.Payload))
		if err == nil {
			handler.HandleMsg(pkt, msg)
		} else {
			log.Printf("!!!! invalid dns pkt: %s\n", err.Error())
		}
	}

	return nil
}
