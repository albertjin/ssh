package ssh

import (
    "errors"
    "io"
    "sync"
)

type ClientOption struct {
	User string
	CheckHostKey func([]byte) error
	GetPassword func() (string, error)
}

type Client struct {
	ClientChannels
	*transport

	actions chan func()

	wait sync.WaitGroup
	reading bool
}

func NewClient(conn io.ReadWriteCloser, option *ClientOption) (*Client, error) {

	s, err := newTransport(conn)
	if err != nil {
		return nil, err
	}

	client := &Client{transport: s}
	client.startLoop()

	done := make(chan int, 1)
	ok := false

	client.do(func() {
        defer func() {
            done<- 0
        }()

        Log(20, "a")
        s.writeKexInit()

        b := <-client.packets

        k, err := s.parseKexinit(b)
        Log(20, "%v", k)
        if err != nil {
            return
        }

        err = s.dh(k, option.CheckHostKey)
        if err != nil {
            return
        }

        for option.GetPassword != nil {
            password, err := option.GetPassword()
            if err != nil {
                return
            }
            if client.auth(option.User, password) {
                break
            }
        }
        Log(20, "b")
        ok = true
    })
    <-done
    if !ok {
        return nil, errors.New("failed")
    }
	return client, nil
}

func (c *Client) Close() {
	c.do(nil)
	c.wait.Wait()
}
