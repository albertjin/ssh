package ssh

import (
)

type ClientChannels struct {
	channels []*Channel
	channelsFreeId []uint32
	channelCount int
}

func (c *Client) ChannelCount() int {
    return c.channelCount
}

func (c *ClientChannels) channelDel(id uint32) {
    c.channelCount--
    c.channels[id] = nil

    if (id + 1) == uint32(len(c.channels)) {
        c.channels = c.channels[:id]
    } else {
        c.channelsFreeId = append(c.channelsFreeId, id)
    }
}

func (c *ClientChannels) channelGet(id uint32) (ch *Channel) {
    return c.channels[id]
}

func (c *ClientChannels) channelAdd(ch *Channel) (id uint32) {
    c.channelCount++
    if n := len(c.channelsFreeId); n > 0 {
        n--
        id = c.channelsFreeId[n]
        c.channelsFreeId = c.channelsFreeId[:n]
        c.channels[id] = ch
    } else {
        id = uint32(len(c.channels))
        c.channels = append(c.channels, ch)
    }
    return
}
