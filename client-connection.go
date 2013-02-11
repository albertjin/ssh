package ssh

import (
	"errors"
	"io"
	"os"
)

type Client struct {
	*ssh
	cc   chan cmd
	chs  map[uint32]*Channel
	lids uint32
	efun func(error)
}

type Channel struct {
	local_id, remote_id         uint32
	local_window, remote_window uint32
	remote_max                  uint32
	state                       uint32
	command                     Command
	efun                        func(error)
	out                         func([]byte)
	err                         func([]byte)
	onclose                     func()
	client                      *Client
	pending                     []byte
}

const (
	chsSpawnCOpen = 1 << iota
	chsReady      = 1 << iota
	chsClosed     = 1 << iota
)

func (c *Client) startLoop() {
	Log(6, "Starting client loop")
	c.cc = make(chan cmd, 16)
	c.chs = map[uint32]*Channel{}
	go c.cloop()
	go func() {
		for {
			b, e := c.ssh.readPacket()
			if e != nil {
				c.efun(e)
			} else {
				c.cc <- cmd{&Packet{b}, nil}
			}
		}
	}()
}

func (c *Client) cloop() {
	for {
		cmd := <-c.cc
		switch v := cmd.Command.(type) {
		case *Spawn:
			if v.In == nil {
				v.In = os.Stdin
			}
			if v.Out == nil {
				v.Out = os.Stdout
			}
			if v.Err == nil {
				v.Err = os.Stderr
			}
			if v.OnClose == nil {
				v.OnClose = func() {}
			}
			ch := cmd.Channel
			ch.local_id = c.lids
			ch.local_window = maxPacketData
			ch.efun = c.efun
			ch.out = func(bs []byte) { v.Out.Write(bs) }
			ch.err = func(bs []byte) { v.Err.Write(bs) }
			ch.onclose = v.OnClose
			c.lids++
			c.chs[ch.local_id] = ch
			c.ssh.writePacket(func(p *Printer) {
				p.Byte(msgChannelOpen).U32String("session").U32(ch.local_id).U32(ch.local_window).U32(maxPacketData)
			})
		case *input:
			ch := cmd.Channel
			ch.pending = append(ch.pending, v.Input...)
			ch.flushInput()
		case *Packet:
			c.dopacket(v.Payload)
		default:
			panic("INVALID VALUE in cloop")
		}
	}
}

func (c *Client) dopacket(b []byte) {
	var code byte

	switch b[0] {
	case msgIgnore:
		Log(5, "Ignoring msgIgnore")
	case msgChannelOpenFailure:
		var cid, reason uint32
		var desc, lang string
		NewParser(b).Byte(&code).U32(&cid).U32(&reason).U32String(&desc).U32String(&lang).End()
		x := c.chs[cid]
		if x != nil {
			x.efun(errors.New(desc))
		}
	case msgChannelWindowAdjust:
		var lcid, wadj uint32
		NewParser(b).Byte(&code).U32(&lcid).U32(&wadj).End()
		x := c.chs[lcid]
		x.remote_window += wadj
	case msgChannelClose:
		var lcid uint32
		NewParser(b).Byte(&code).U32(&lcid).End()
		x := c.chs[lcid]
		delete(c.chs, lcid)
		if x.state != chsClosed {
			x.state = chsClosed
			x.onclose()
			c.ssh.writePacket(func(p *Printer) {
				p.Byte(msgChannelClose).U32(x.remote_id)
			})
		}
	case msgChannelEof:
		Log(5, "Ignoring msgChannelEof")
	case msgChannelRequest:
		Log(5, "Ignoring msgChannelRequest")
	case msgChannelSuccess:
		Log(5, "Ignoring msgChannelSuccess")
	case msgChannelFailure:
		var lcid uint32
		NewParser(b).Byte(&code).U32(&lcid).End()
		x := c.chs[lcid]
		x.efun(errors.New("Channel failure"))
	case msgChannelData:
		var lcid uint32
		var data []byte
		NewParser(b).Byte(&code).U32(&lcid).U32Bytes(&data).End()
		x := c.chs[lcid]
		x.out(data)
		c.ssh.writePacket(func(p *Printer) {
			p.Byte(msgChannelWindowAdjust).U32(x.remote_id).U32(0)
		})
	case msgChannelExtendedData:
		var lcid, dtc uint32
		var data []byte
		NewParser(b).Byte(&code).U32(&lcid).U32(&dtc).U32Bytes(&data).End()
		x := c.chs[lcid]
		x.err(data)
		c.ssh.writePacket(func(p *Printer) {
			p.Byte(msgChannelWindowAdjust).U32(x.remote_id).U32(uint32(0))
		})
	case msgChannelOpenConfirmation:
		var lcid, rcid, rwin, rmax uint32
		NewParser(b).Byte(&code).U32(&lcid).U32(&rcid).U32(&rwin).U32(&rmax).End()
		Log(6, "lcid %d, rcid %d, rwin %d, rmax %d\n", lcid, rcid, rwin, rmax)
		x := c.chs[lcid]
		x.remote_id = rcid
		x.remote_window = rwin
		x.remote_max = rmax
		x.state = chsReady

		switch v := x.command.(type) {
		case *Spawn:
			if !v.NoTTY {
				c.ssh.writePacket(func(p *Printer) {
					p.Byte(msgChannelRequest).U32(x.remote_id).U32String("pty-req")
					p.Byte(0).U32String(os.Getenv("TERM"))
					p.U32(0).U32(0).U32(0).U32(0).U32String("")
				})
			}
			if v.Cmd == "" {
				c.ssh.writePacket(func(p *Printer) {
					p.Byte(msgChannelRequest).U32(x.remote_id).U32String("shell").Byte(1)
				})
			} else {
				c.ssh.writePacket(func(p *Printer) {
					p.Byte(msgChannelRequest).U32(x.remote_id).U32String("exec").Byte(1).U32String(v.Cmd)
				})
			}
		default:
			panic("dopacket: unknown command type")
		}
	default:
		Log(0, "Packet %d %X", b[0], b)
		panic("dopacket: Unknown packet")
	}
}

func (c *Channel) flushInput() {
	if c.state != chsReady {
		return
	}
	n := min(min(len(c.pending), int(c.remote_window)), min(int(c.remote_max), int(maxPacketData)))
	if n == 0 {
		return
	}
	c.client.ssh.writePacket(func(p *Printer) {
		p.Byte(msgChannelData).U32(c.remote_id).U32Bytes(c.pending[0:n])
	})
	c.remote_window -= uint32(n)
	c.pending = c.pending[n:]
}

type Command interface {
	isc()
}

type cmd struct {
	Command Command
	Channel *Channel
}

type Spawn struct {
	Cmd      string
	In       io.ReadCloser
	Out, Err io.WriteCloser
	NoTTY    bool
	OnClose  func()
}

type Packet struct {
	Payload []byte
}

type input struct {
	Input []byte
}

func (*Spawn) isc()  {}
func (*Packet) isc() {}
func (*input) isc()  {}

func (c *Client) Cmd(Command Command) *Channel {
	ch := &Channel{}
	ch.command = Command
	ch.client = c
	c.cc <- cmd{Command, ch}
	return ch
}

func (ch *Channel) Write(bs []byte) (int, error) {
	ch.client.cc <- cmd{&input{bs}, ch}
	return len(bs), nil
}
