package kcp

import (
	"fmt"
	"net"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

type Conn struct {
	PacketConn *socket.PacketConn
	UDPSession *kcp.UDPSession
	Session    *smux.Session
	closeChan  chan struct{}
}

func (c *Conn) OpenStrm() (tnet.Strm, error) {
	strm, err := c.Session.OpenStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) AcceptStrm() (tnet.Strm, error) {
	strm, err := c.Session.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &Strm{strm}, nil
}

func (c *Conn) Ping(wait bool) error {
	strm, err := c.Session.OpenStream()
	if err != nil {
		return fmt.Errorf("ping failed: %v", err)
	}
	defer strm.Close()
	if wait {
		p := protocol.Proto{Type: protocol.PPING}
		err = p.Write(strm)
		if err != nil {
			return fmt.Errorf("strm ping write failed: %v", err)
		}
		err = p.Read(strm)
		if err != nil {
			return fmt.Errorf("strm ping read failed: %v", err)
		}
		if p.Type != protocol.PPONG {
			return fmt.Errorf("strm pong failed: %v", err)
		}
	}
	return nil
}

func (c *Conn) Close() error {
	var err error
	if c.closeChan != nil {
		select {
		case <-c.closeChan:
		default:
			close(c.closeChan)
		}
	}
	if c.UDPSession != nil {
		c.UDPSession.Close()
	}
	if c.Session != nil {
		c.Session.Close()
	}
	if c.PacketConn != nil {
		c.PacketConn.Close()
	}
	return err
}

func (c *Conn) StartAdaptiveRateControl() {
	if c.PacketConn == nil {
		return
	}
	if c.closeChan == nil {
		c.closeChan = make(chan struct{})
	}
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		var lastRetrans, lastOut uint64
		stats := kcp.DefaultSnmp.Copy()
		lastRetrans = stats.RetransSegs
		lastOut = stats.OutSegs

		for {
			select {
			case <-ticker.C:
				stats := kcp.DefaultSnmp.Copy()
				retrans := stats.RetransSegs - lastRetrans
				out := stats.OutSegs - lastOut

				if out > 0 {
					loss := float64(retrans) / float64(out+retrans) * 100.0
					c.PacketConn.AdaptiveAdjust(loss)
				}

				lastRetrans = stats.RetransSegs
				lastOut = stats.OutSegs
			case <-c.closeChan:
				return
			}
		}
	}()
}

func (c *Conn) LocalAddr() net.Addr                { return c.Session.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.Session.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.Session.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.UDPSession.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.UDPSession.SetWriteDeadline(t) }
