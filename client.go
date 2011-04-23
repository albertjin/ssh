package ssh

import "os"

type C struct {
	User string
	Host string
	HostKeyFun  func([]byte)os.Error
	PasswordFun func()string
}

func New(C C) (*Client,os.Error) {
	c,e := connect(C.Host)
	if e != nil { return nil,e }
	writeKexInit(c)
	b,e := readPacket(c)
	c.skex = make([]byte, len(b))
	copy(c.skex, b)
	if e!=nil { return nil,e }
	k,e := parseKexInit(c,b[1:])
	Log(6,"%v",k)
	if e!=nil { return nil,e }
	e = dh(c,k,&C)
	if e!=nil { return nil,e }

	client := &Client{ssh: c}
	for C.PasswordFun!=nil && !password(c,C.User, C.PasswordFun()) {}
	startClientLoop(client)
	return client, nil
}


