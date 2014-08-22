package ssh

import (
    "errors"
    "io"
)

type TunnelConn struct {
    *Channel
    packet []byte
    packets chan []byte
}

func (s *TunnelConn) send(data []byte) {
    s.packets<- data
}

func (s *TunnelConn) recv() {
    select {
    case s.packet = <-s.packets:
    default:
        s.moreData()
        s.packet = <-s.packets
    }
}

func (s *TunnelConn) init() {
    <-s.packets
}

func (s *TunnelConn) Read(buf []byte) (n int, err error) {
    if len(buf) > 0 {
        if len(s.packet) == 0 {
            s.recv()
        }

        if len(s.packet) > 0 {
            n = copy(buf, s.packet)
            s.packet = s.packet[n:]
        } else {
            s.send(nil)
            err = io.EOF
        }
    }
    return
}

func (s *TunnelConn) Read2(buf []byte) (data []byte, err error) {
    n := len(buf)

    if n == 0 {
        return
    }

    if len(s.packet) == 0 {
        s.recv()
    }

    if m := len(s.packet); m > 0 {
        if m > n {
            data, s.packet = s.packet[:n], s.packet[n:]
        } else {
            data, s.packet = s.packet, nil
        }
    } else {
        err = io.EOF
    }

    return
}

func (c *Client) DialTCP(host string, port int) (conn *TunnelConn, err error) {
    conn = &TunnelConn{packets: make(chan []byte, 128)}

	ch := &Channel{localWindow: 128*1024, client: c, opened: false, ChannelSink: &ChannelSink {
        OnChannelEOF: func(ch *Channel) {
            Log(20, "OnChannelEOF %v", ch.RemoteId())
            //conn.send(nil)
        },

        OnChannelClose: func(ch *Channel) {
            Log(20, "OnChannelClose %v", ch.RemoteId())
            conn.send(nil)
        },

        OnChannelData: func(ch *Channel, data []byte) {
            conn.send(data)
        },

        OnChannelExtendedData: func(ch *Channel, data []byte, dataType uint32) {
            Log(20, "OnChannelExtendedData %v %v", ch.RemoteId(), dataType)
        },

        OnChannelOpenConfirmation: func(ch *Channel) {
            Log(20, "OnChannelOpenConfirmation %v", ch.RemoteId())
            conn.send(nil)
        },

        OnChannelOpenFailure: func(ch *Channel, reason uint32, description, lang string) {
            Log(20, "OnChannelOpenFailure reason: [%v] description: [%v]", reason, description)
            err = errors.New("open channel failure")
            conn.send(nil)
        },
    }}
    conn.Channel = ch

	c.do(func() {
        /* ChanType:      "direct-tcpip",
           PeersId:       localId,
           PeersWindow:   ch.localWindow,
           MaxPacketSize: MaxPacketSize,
           raddr:         host,
           rport:         uint32(port),
           laddr:         "0.0.0.0",
           lport:         uint32(0),
        */

        localId := c.channelAdd(ch)
        _, err = ch.Client().Packet().Byte(MsgChannelOpen).
            U32String("direct-tcpip").U32(localId).U32(ch.localWindow).U32(MaxPacketSize).
            U32String(host).U32(uint32(port)).
            U32String("0.0.0.0").U32(0).
            Commit()
        if err != nil {
            c.channelDel(localId)
            conn.send(nil)
        }
	})

    if conn.init(); err != nil {
        conn = nil
    }
    return
}
