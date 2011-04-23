package ssh

import (
	"bitbucket.org/taruti/bigendian"
	"io"
	"os"
	)

type Client struct {
	*ssh
	cc  chan cmd
	chs map[uint32]*Channel
	lids uint32
}

type Channel struct {
	local_id, remote_id uint32
	local_window, remote_window uint32
	remote_max uint32
	state uint32
	command Command
	efun func(os.Error)
	out  func([]byte)
	err  func([]byte)
	client *Client
	pending []byte
}

const (
	chsSpawnCOpen = 1 << iota
	chsReady      = 1 << iota
)

func startClientLoop(c *Client) {
	Log(6, "Starting client loop")
	c.cc = make(chan cmd, 16)
	c.chs= map[uint32]*Channel{}
	go cloop(c)
	go func(){
		for {
			b,e := readPacket(c.ssh)
			if e!=nil { panic(e) }
			c.cc <- cmd{&Packet{b}, nil}
		}
	}()
}

func cloop(c *Client) {
	for {
		cmd :=<- c.cc
		switch v := cmd.Command.(type) {
		case *Spawn:
			if v.Efun == nil {
				v.Efun = func(e os.Error) { panic(e) }
			}
			if v.In == nil {
				v.In = os.Stdin
			}
			if v.Out == nil {
				v.Out = os.Stdout
			}
			if v.Err == nil {
				v.Out = os.Stderr
			}
			ch := cmd.Channel
			ch.local_id     = c.lids
			ch.local_window = maxPacketData
			ch.efun         = v.Efun
			ch.out          = func(bs []byte) { v.Out.Write(bs) }
			ch.err          = func(bs []byte) { v.Err.Write(bs) }
			c.lids++
			c.chs[ch.local_id] = ch
			writePacket(c.ssh, func(p*bigendian.Printer){
				p.Byte(msgChannelOpen).U32String("session").U32(ch.local_id).U32(ch.local_window).U32(maxPacketData)
			})
		case *input:
			ch := cmd.Channel
			ch.pending = append(ch.pending, v.Input...)
			flushInput(ch)
		case *Packet:
			dopacket(c,v.Payload)
		default:
			panic("INVALID VALUE in cloop")
		}
	}
}

func dopacket(c *Client, b []byte) {
	var code byte
	
	switch b[0] {
	case msgChannelOpenFailure:
		var cid, reason uint32
		var desc, lang string
		bigendian.NewParser(b).Byte(&code).U32(&cid).U32(&reason).U32String(&desc).U32String(&lang).End()
		x := c.chs[cid]
		if x!=nil {
			x.efun(os.NewError(desc))
		}
	case msgChannelWindowAdjust:
		var lcid, wadj uint32
		bigendian.NewParser(b).Byte(&code).U32(&lcid).U32(&wadj).End()
		x := c.chs[lcid]
		x.remote_window += wadj
	case msgChannelSuccess:
	case msgChannelFailure:
		var lcid uint32
		bigendian.NewParser(b).Byte(&code).U32(&lcid).End()
		x := c.chs[lcid]
		x.efun(os.NewError("Channel failure"))
	case msgChannelData:
		var lcid uint32
		var data []byte
		bigendian.NewParser(b).Byte(&code).U32(&lcid).U32Bytes(&data).End()
		x := c.chs[lcid]
		x.out(data)
		writePacket(c.ssh, func(p*bigendian.Printer) {
			p.Byte(msgChannelWindowAdjust).U32(x.remote_id).U32(uint32(len(data)))
		})
	case msgChannelExtendedData:
		var lcid, dtc uint32
		var data []byte
		bigendian.NewParser(b).Byte(&code).U32(&lcid).U32(&dtc).U32Bytes(&data).End()
		x := c.chs[lcid]
		x.err(data)
		writePacket(c.ssh, func(p*bigendian.Printer) {
			p.Byte(msgChannelWindowAdjust).U32(x.remote_id).U32(uint32(len(data)))
		})
	case msgChannelOpenConfirmation:
		var lcid, rcid, rwin, rmax uint32
		bigendian.NewParser(b).Byte(&code).U32(&lcid).U32(&rcid).U32(&rwin).U32(&rmax).End()
		Log(6,"lcid %d, rcid %d, rwin %d, rmax %d\n",lcid, rcid, rwin, rmax)
		x := c.chs[lcid]
		x.remote_id = rcid
		x.remote_window = rwin
		x.remote_max = rmax
		x.state = chsReady

		switch v := x.command.(type) {
		case *Spawn:
			if !v.NoTTY {
				writePacket(c.ssh, func(p*bigendian.Printer) {
					p.Byte(msgChannelRequest).U32(x.remote_id).U32String("pty-req")
					p.Byte(0).U32String(os.Getenv("TERM"))
					p.U32(0).U32(0).U32(0).U32(0).U32String("")
				})
			}
			if v.Cmd=="" {
				writePacket(c.ssh, func(p*bigendian.Printer) {
					p.Byte(msgChannelRequest).U32(x.remote_id).U32String("shell").Byte(1)
				})
			} else {
				writePacket(c.ssh, func(p*bigendian.Printer) {
					p.Byte(msgChannelRequest).U32(x.remote_id).U32String("exec").Byte(1).U32String(v.Cmd)
				})
			}
		default:
			panic("dopacket: unknown command type")
		}
	default:
		panic("dopacket: Unknown packet")
	}
}

func flushInput(c *Channel) {
	if c.state != chsReady {
		return
	}
	n := min(min(len(c.pending),int(c.remote_window)), min(int(c.remote_max), int(maxPacketData)))
	if n == 0 {
		return
	}
	writePacket(c.client.ssh, func(p*bigendian.Printer) {
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
	Cmd string
	In io.ReadCloser
	Out,Err io.WriteCloser
	Efun func(os.Error)
	NoTTY bool
}

type Packet struct {
	Payload []byte
}

type input struct {
	Input   []byte
}


func (*Spawn)isc() {}
func (*Packet)isc() {}
func (*input)isc() {}

func (c *Client)Cmd(Command Command) *Channel {
	ch := &Channel{}
	ch.command      = Command
	ch.client       = c
	c.cc <- cmd{Command,ch}
	return ch
}

func (ch *Channel) Write(bs []byte) (int,os.Error) {
	ch.client.cc <- cmd{&input{bs},ch}
	return len(bs),nil
}