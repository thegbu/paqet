package socket

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

type SendHandle struct {
	handle      *pcap.Handle
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	time        uint32
	tsCounter   uint32
	tcpF        TCPF
	

	seqTracker  *SeqTracker
	portPool    *PortPool
	rateLimiter *RateLimiter

	synOptions  []layers.TCPOption
	ackOptions  []layers.TCPOption
	ethPool     sync.Pool
	ipv4Pool    sync.Pool
	ipv6Pool    sync.Pool
	tcpPool     sync.Pool
	bufPool     sync.Pool
	rawBufPool  sync.Pool
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	sh := &SendHandle{
		handle:     handle,
		srcPort:    uint16(cfg.Port),
		tcpF:       TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:       uint32(time.Now().UnixNano() / int64(time.Millisecond)),

		seqTracker: NewSeqTracker(cfg.TCPState.CleanupInterval, cfg.TCPState.ConnectionTimeout),
		rateLimiter: NewRateLimiter(RateLimiterConfig{
			Enabled:          cfg.RateLimit.Enabled,
			PacketsPerSecond: cfg.RateLimit.PacketsPerSecond,
			Burst:            cfg.RateLimit.Burst,
			Adaptive:         cfg.RateLimit.Adaptive,
		}),
		synOptions: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
		},
		ackOptions: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		},
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any {
				return &layers.IPv4{
					Version:  4,
					IHL:      5,
					TOS:      184,
					TTL:      64,
					Protocol: layers.IPProtocolTCP,
				}
			},
		},
		ipv6Pool: sync.Pool{
			New: func() any {
				return &layers.IPv6{
					Version:    6,
					HopLimit:   64,
					NextHeader: layers.IPProtocolTCP,
				}
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				return &layers.TCP{}
			},
		},
		bufPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBuffer()
			},
		},
		rawBufPool: sync.Pool{
			New: func() any {
				return make([]byte, 2048)
			},
		},
	}
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	

	var errPool error
	sh.portPool, errPool = NewPortPool(PortPoolConfig{
		Enabled:   cfg.PortPool.Enabled,
		StartPort: cfg.PortPool.StartPort,
		EndPort:   cfg.PortPool.EndPort,
	})
	if errPool != nil {
		return nil, fmt.Errorf("failed to create port pool: %w", errPool)
	}
	
	return sh, nil
}

func (h *SendHandle) buildTCPHeader(dstIP net.IP, dstPort uint16, f conf.TCPF, payloadLen int) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)
	

	srcPort := h.srcPort
	if h.portPool != nil {
		allocated := h.portPool.AllocatePort(dstIP, dstPort)
		if allocated != 0 {
			srcPort = allocated
		}
	}
	

	var seq, ack uint32
	useTracker := h.seqTracker != nil && (h.seqTracker.cleanupInterval > 0 || h.seqTracker.maxIdleTime > 0)
	
	if useTracker {
		seq, ack = h.seqTracker.GetSeqAck(dstIP, dstPort, payloadLen)
	} else {

		counter := atomic.AddUint32(&h.tsCounter, 1)
		if f.SYN {
			seq = 1 + (counter & 0x7)
			ack = 0
			if f.ACK {
				ack = seq + 1
			}
		} else {
			seq = h.time + (counter << 7)
			ack = seq - (counter & 0x3FF) + 1400
		}
	}

	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     seq,
		Ack:     ack,
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window:  65535,
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	if f.SYN {
		tcp.Options = h.synOptions
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[4:8], 0)
		if !useTracker {
			tcp.Seq = 1 + (counter & 0x7)
			tcp.Ack = 0
			if f.ACK {
				tcp.Ack = tcp.Seq + 1
			}
		}
	} else {
		tcp.Options = h.ackOptions
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(tcp.Options[2].OptionData[4:8], tsEcr)
		if !useTracker {
			seq := h.time + (counter << 7)
			tcp.Seq = seq
			tcp.Ack = seq - (counter & 0x3FF) + 1400
		}
	}

	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	if h.rateLimiter != nil {
		h.rateLimiter.Wait(context.Background())
	}

	dstIP4 := dstIP.To4()
	if dstIP4 == nil {
		return h.writeGeneric(payload, addr)
	}

	f := h.getClientTCPF(dstIP, dstPort)
	seq, ack, _ := h.getSeqAck(dstIP, dstPort, f, len(payload))

	buf := h.rawBufPool.Get().([]byte)
	defer h.rawBufPool.Put(buf)

	ethHeader := h.ethPool.Get().(*layers.Ethernet)
	copy(buf[0:6], h.srcIPv4RHWA)
	copy(buf[6:12], ethHeader.SrcMAC)
	h.ethPool.Put(ethHeader)
	binary.BigEndian.PutUint16(buf[12:14], uint16(layers.EthernetTypeIPv4))

	buf[14] = 0x45
	buf[15] = 184
	ipLen := uint16(20 + 20 + len(payload))
	optionsLen := 12
	if f.SYN {
		optionsLen = 20
	}
	ipLen += uint16(optionsLen)
	binary.BigEndian.PutUint16(buf[16:18], ipLen)
	binary.BigEndian.PutUint16(buf[18:20], 0)
	binary.BigEndian.PutUint16(buf[20:22], 0x4000)
	buf[22] = 64
	buf[23] = 6
	binary.BigEndian.PutUint16(buf[24:26], 0)
	copy(buf[26:30], h.srcIPv4.To4())
	copy(buf[30:34], dstIP4)

	binary.BigEndian.PutUint16(buf[24:26], h.calculateIPChecksum(buf[14:34]))

	srcPort := h.srcPort
	if h.portPool != nil {
		allocated := h.portPool.AllocatePort(dstIP, dstPort)
		if allocated != 0 {
			srcPort = allocated
		}
	}
	binary.BigEndian.PutUint16(buf[34:36], srcPort)
	binary.BigEndian.PutUint16(buf[36:38], dstPort)
	binary.BigEndian.PutUint32(buf[38:42], seq)
	binary.BigEndian.PutUint32(buf[42:46], ack)
	
	dataOffset := uint8((20 + optionsLen) / 4)
	buf[46] = (dataOffset << 4)
	buf[47] = h.getTCPFlags(f)
	binary.BigEndian.PutUint16(buf[48:50], 65535)
	binary.BigEndian.PutUint16(buf[50:52], 0)
	binary.BigEndian.PutUint16(buf[52:54], 0)

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	if f.SYN {
		buf[54], buf[55], buf[56], buf[57] = 2, 4, 0x05, 0xb4
		buf[58], buf[59] = 4, 2
		buf[60], buf[61] = 8, 10
		binary.BigEndian.PutUint32(buf[62:66], tsVal)
		binary.BigEndian.PutUint32(buf[66:70], 0)
		buf[70] = 1
		buf[71], buf[72], buf[73] = 3, 3, 8
	} else {
		buf[54], buf[55] = 1, 1
		buf[56], buf[57] = 8, 10
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(buf[58:62], tsVal)
		binary.BigEndian.PutUint32(buf[62:66], tsEcr)
	}

	headerLen := 54 + optionsLen
	copy(buf[headerLen:headerLen+len(payload)], payload)

	binary.BigEndian.PutUint16(buf[50:52], h.calculateTCPChecksum(buf[26:34], buf[34:headerLen+len(payload)]))

	return h.handle.WritePacketData(buf[:headerLen+len(payload)])
}

func (h *SendHandle) getSeqAck(dstIP net.IP, dstPort uint16, f conf.TCPF, payloadLen int) (seq, ack uint32, useTracker bool) {
	useTracker = h.seqTracker != nil && (h.seqTracker.cleanupInterval > 0 || h.seqTracker.maxIdleTime > 0)
	if useTracker {
		seq, ack = h.seqTracker.GetSeqAck(dstIP, dstPort, payloadLen)
	} else {
		counter := atomic.LoadUint32(&h.tsCounter)
		if f.SYN {
			seq = 1 + (counter & 0x7)
			ack = 0
			if f.ACK {
				ack = seq + 1
			}
		} else {
			seq = h.time + (counter << 7)
			ack = seq - (counter & 0x3FF) + 1400
		}
	}
	return
}

func (h *SendHandle) getTCPFlags(f conf.TCPF) uint8 {
	var r uint8
	if f.FIN { r |= 0x01 }
	if f.SYN { r |= 0x02 }
	if f.RST { r |= 0x04 }
	if f.PSH { r |= 0x08 }
	if f.ACK { r |= 0x10 }
	if f.URG { r |= 0x20 }
	if f.ECE { r |= 0x40 }
	if f.CWR { r |= 0x80 }
	return r
}

func (h *SendHandle) calculateIPChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (h *SendHandle) calculateTCPChecksum(pseudoHeader, tcpData []byte) uint16 {
	var sum uint32
	for i := 0; i < len(pseudoHeader); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudoHeader[i : i+2]))
	}
	sum += uint32(6)
	sum += uint32(len(tcpData))

	for i := 0; i < len(tcpData)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcpData[i : i+2]))
	}
	if len(tcpData)%2 == 1 {
		sum += uint32(tcpData[len(tcpData)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (h *SendHandle) writeGeneric(payload []byte, addr *net.UDPAddr) error {
	dstIP := addr.IP
	dstPort := uint16(addr.Port)
	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(dstIP, dstPort, f, len(payload))
	defer h.tcpPool.Put(tcpLayer)

	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
	}()

	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	defer h.ethPool.Put(ethLayer)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.ipv4Pool.Get().(*layers.IPv4)
		defer h.ipv4Pool.Put(ip)
		ip.SrcIP = h.srcIPv4
		ip.DstIP = dstIP
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.ipv6Pool.Get().(*layers.IPv6)
		defer h.ipv6Pool.Put(ip)
		ip.SrcIP = h.srcIPv6
		ip.DstIP = dstIP
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		return err
	}
	return h.handle.WritePacketData(buf.Bytes())
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
	if h.seqTracker != nil {
		h.seqTracker.Close()
	}
}
