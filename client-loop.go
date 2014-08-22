package ssh

func (c *Client) startLoop() {
    c.wait.Add(1); defer c.wait.Done()

	Log(6, "Starting client loop")
	c.actions = make(chan func(), 256*1024)
	c.channels = make([]*Channel, 0, 1024)

    c.wait.Add(2)
	c.reading = true

	go c.loop1()
	go c.loop2()
}

func (c *Client) do(action func()) {
    c.actions<- action
}

func (c *Client) getRequest() (action func()) {
    action = <-c.actions
    return
}

func (c *Client) loop1() {
    defer func() {
        if r := recover(); r != nil {
            Log(10, "panic: loop() %v", r)
        }

        Log(10, "loop() exit")
        c.wait.Done()
    }()

	for running := true; running; {
	    select {
        case action := <-c.actions:
            if action != nil {
                action()
            } else {
                running = false
            }

        case packet := <-c.packets:
            if packet != nil {
                c.handlePacket(packet)
            } else {
                running = false
            }
        }
	}

    if c.conn != nil {
        var err error
        for _, ch := range c.channels {
            if ch != nil {
                err = ch.sendClose()
                if err != nil {
                    break
                }
            }
        }

        if err == nil {
            for c.reading && (c.channelCount > 0) {
                request := c.getRequest()
                if request == nil { break }
                request()
            }
        }

        close(c.actions)
        c.conn.Close()
    }
}

func (c *Client) loop2() {
    defer func() {
        if r := recover(); r != nil {
            Log(10, "panic: loop2() %v", r)
        }

        Log(10, "loop2() exit")
        c.reading = false
        c.wait.Done()
    }()

    for {
        packet, err := c.readPacket()
        if len(packet) == 0 {
            Log(20, "loop2 %v", err)
            c.packets<- nil
            break
        } else {
            c.packets<- packet
            if packet[0] == MsgNewkeys {
                <-c.newkey
            }
        }
    }
}
