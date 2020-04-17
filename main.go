package main

import (
	"log"
	"sync"
	"time"

	"github.com/ben-han-cn/cement/signal"
	"github.com/ben-han-cn/g53"
	"github.com/ben-han-cn/livedns/packet"
	"github.com/ben-han-cn/livedns/util"
)

type Query struct {
	conflictKey uint64
	question    string
	time        time.Time
}

type DNSMessageMonitor struct {
	unfinishedQuery map[uint64]Query
	mu              sync.Mutex
}

func newMonitor() *DNSMessageMonitor {
	return &DNSMessageMonitor{
		unfinishedQuery: make(map[uint64]Query),
	}
}

func (m *DNSMessageMonitor) HandleMsg(pkt packet.Packet, msg *g53.Message) {
	key, conflictKey := util.HashQuery(msg.Question.Name, msg.Question.Type)
	isResponse := msg.Header.GetFlag(g53.FLAG_QR)

	m.mu.Lock()
	defer m.mu.Unlock()

	if isResponse {
		if query, ok := m.unfinishedQuery[key]; ok {
			if query.conflictKey == conflictKey {
				delete(m.unfinishedQuery, key)
				log.Printf("%s get response %s from %v\n", msg.Question.String(), msg.Header.Rcode.String(), pkt.SrcIP)
			}
		}
	} else {
		m.unfinishedQuery[key] = Query{
			conflictKey: conflictKey,
			question:    msg.Question.String(),
			time:        time.Now(),
		}
	}
}

func (m *DNSMessageMonitor) DisplayUnfinishedQuery() {
	m.mu.Lock()
	defer m.mu.Unlock()
	checkLen := len(m.unfinishedQuery)
	if checkLen > 10 {
		checkLen = 10
	}

	cleanKey := make([]uint64, 0, checkLen)
	for k, q := range m.unfinishedQuery {
		if checkLen == 0 {
			break
		} else {
			checkLen -= 1
		}

		if delay := time.Since(q.time); delay > 5*time.Second {
			log.Printf("!!! q %s is delayed: %v\n", q.question, delay)
			cleanKey = append(cleanKey, k)
		}
	}

	for _, k := range cleanKey {
		delete(m.unfinishedQuery, k)
	}
}

func main() {
	source, err := packet.NewIfaceReader("en0", false)
	if err != nil {
		log.Fatalf("create reader failed:%s", err.Error())
	}

	monitor := newMonitor()
	go packet.RunDNSMessagePump(source, monitor)

	timer := time.NewTicker(time.Duration(10) * time.Second)
	go func() {
		for {
			<-timer.C
			monitor.DisplayUnfinishedQuery()
		}
	}()

	signal.WaitForInterrupt(func() {
		timer.Stop()
		source.Stop()
	})
}
