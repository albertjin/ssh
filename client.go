package ssh

type C struct {
	User        string
	Host        string
	HostKeyFun  func([]byte) error
	PasswordFun func() (string, error)
	ErrorFun    func(error)
}

func New(C C) (*Client, error) {
	c, e := connect(C.Host)
	if e != nil {
		return nil, e
	}
	c.writeKexInit()
	b, e := c.readPacket()
	c.skex = make([]byte, len(b))
	copy(c.skex, b)
	if e != nil {
		return nil, e
	}
	k, e := c.parseKexInit(b[1:])
	Log(6, "%v", k)
	if e != nil {
		return nil, e
	}
	e = c.dh(k, &C)
	if e != nil {
		return nil, e
	}

	client := &Client{ssh: c, efun: C.ErrorFun}
	for C.PasswordFun != nil {
		pass, err := C.PasswordFun()
		if err != nil {
			return nil, err
		}
		if c.password(C.User, pass) {
			break
		}
	}
	client.startLoop()
	return client, nil
}
