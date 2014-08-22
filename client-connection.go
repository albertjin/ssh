package ssh

import (
)

func (c *Client) handlePacket(packet []byte) {
    code, packetData := packet[0], packet[1:]

    switch code {
    case MsgIgnore:
        Log(20, "Ignoring MsgIgnore")

    case MsgChannelWindowAdjust:
        var localId, wadj uint32
        NewDecoder(packetData).U32(&localId).U32(&wadj).End()

        ch := c.channelGet(localId)
        ch.remoteWindow += wadj
        Log(5, "MsgChannelWindowAdjust %v %v", ch.remoteId, ch.remoteWindow)
        ch.sendData()

    case MsgChannelClose:
        var localId uint32
        NewDecoder(packetData).U32(&localId).End()

        ch := c.channelGet(localId)
        c.channelDel(localId)
        ch.sendClose()
        if ch.OnChannelClose != nil {
            ch.OnChannelClose(ch)
        }

    case MsgChannelEOF:
        var localId uint32
        NewDecoder(packetData).U32(&localId).End()

        ch := c.channelGet(localId)
        if ch.OnChannelEOF != nil {
            ch.OnChannelEOF(ch)
        }

    case MsgChannelRequest:
        Log(20, "Ignoring MsgChannelRequest")

    case MsgChannelSuccess:
        Log(20, "Ignoring MsgChannelSuccess")

    case MsgChannelFailure:
        Log(20, "Ignoring MsgChannelFailure")

    case MsgChannelData:
        var localId uint32
        var data []byte
        NewDecoder(packetData).U32(&localId).U32Bytes(&data).End()

        ch := c.channelGet(localId)
        ch.updateWindow(data)
        if ch.OnChannelData != nil {
            ch.OnChannelData(ch, data)
        }

    case MsgChannelExtendedData:
        var localId, dataType uint32
        var data []byte
        NewDecoder(packetData).U32(&localId).U32(&dataType).U32Bytes(&data).End()

        ch := c.channelGet(localId)
        ch.updateWindow(data)
        if ch.OnChannelExtendedData != nil {
            ch.OnChannelExtendedData(ch, data, dataType)
        }

    case MsgChannelOpenConfirmation:
        var localId, remoteId, remoteWindow, remoteMaxPacketSize uint32
        NewDecoder(packetData).U32(&localId).U32(&remoteId).U32(&remoteWindow).U32(&remoteMaxPacketSize).End()

        Log(5, "MsgChannelOpenConfirmation %v %v %v %v", localId, remoteId, remoteWindow, remoteMaxPacketSize)
        ch := c.channelGet(localId)
        if ch.opened { panic("MsgChannelOpenConfirmation: logic error") }

        ch.opened = true
        ch.remoteId = remoteId
        ch.remoteWindow = remoteWindow
        ch.remoteMaxPacketSize = remoteMaxPacketSize

        if ch.OnChannelOpenConfirmation != nil {
            ch.OnChannelOpenConfirmation(ch)
        }

    case MsgChannelOpenFailure:
        var localId, reason uint32
        var description, lang string
        NewDecoder(packetData).U32(&localId).U32(&reason).U32String(&description).U32String(&lang).End()

        ch := c.channelGet(localId)
        c.channelDel(localId)
        if ch.OnChannelOpenFailure != nil {
            ch.OnChannelOpenFailure(ch, reason, description, lang)
        }

    case MsgKexinit:
        Log(20, "MsgKexinit")
        c.writeKexInit()

        k, err := c.parseKexinit(packet)
        Log(20, "MsgKexinit %v", err)
        err = c.dh(k, nil)
        Log(20, "MsgKexinit %v", err)

    default:
        Log(20, "msgUnknown %v %v", code, packetData)
    }
}
