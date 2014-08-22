package ssh

import (
    "errors"
)

type ChannelSink struct {
	OnChannelFailure func(ch *Channel)
	OnChannelClose func(ch *Channel)
	OnChannelEOF func(ch *Channel)
	OnChannelExtendedData func(ch *Channel, data []byte, dataType uint32)
	OnChannelData func(ch *Channel, data []byte)
	OnChannelOpenConfirmation func(ch *Channel)
	OnChannelOpenFailure func(ch *Channel, reason uint32, description, lang string)
}

type Channel struct {
    *ChannelSink
	client *Client

	localId, localWindow, remoteId, remoteWindow, remoteMaxPacketSize uint32

	opened bool
	received uint32
	sending []byte
}

func (ch *Channel) Client() *Client {
    return ch.client
}

func (ch *Channel) RemoteId() uint32 {
    return ch.remoteId
}

func (ch *Channel) Write(data []byte) (n int, err error) {
    defer func() {
        if r := recover(); r != nil {
            err = errors.New("write")
        }
    }()

    n = len(data)
    cached := make([]byte, len(data))
    copy(cached, data)
    if n > 0 {
        ch.client.do(func() {
            if len(ch.sending) == 0 {
                ch.sending = cached
            } else {
                ch.sending = append(ch.sending, cached...)
            }
            ch.sendData()
        })
    }
	return
}

func (ch *Channel) Close() (err error) {
    defer func() {
        if r := recover(); r != nil {
            err = errors.New("close")
        }
    }()

    ch.client.do(func() {
        ch.sendClose()
    })
    return
}

func (ch *Channel) sendClose() (err error) {
    if ch.opened {
        ch.sendData()
        ch.opened = false
        _, err = ch.client.Packet().Byte(MsgChannelClose).U32(ch.remoteId).Commit()
    }
    return
}

func (ch *Channel) sendData() (err error) {
	if !ch.opened {
	    err = errors.New("cannot send on closed channel")
	    Log(20, "%v", err)
		return
	}

	if ch.remoteWindow == 0 {
	    return
	}

	n := len(ch.sending)
	if n == 0 {
		return
	}

	if m := int(ch.remoteMaxPacketSize-9); n > m {
	    n = m
	}

	if m := int(ch.remoteWindow); n > m {
	    n = m
	}

    ch.remoteWindow -= uint32(n)
	_, err = ch.client.Packet().Byte(MsgChannelData).U32(ch.remoteId).U32Bytes(ch.sending[:n]).Commit()
	ch.sending = ch.sending[n:]
	return
}

func (ch *Channel) updateWindow(data []byte) {
    ch.received += uint32(len(data))
}

func (ch *Channel) moreData() {
    ch.client.do(func() {
        if ch.opened && (ch.localWindow < (ch.received + MaxPacketSize)) {
            delta := ch.received
            ch.received = 0

            ch.client.Packet().Byte(MsgChannelWindowAdjust).U32(ch.remoteId).U32(delta).Commit()
        }
    })
}
