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
	writeKexInit(c)
	b, e := readPacket(c)
	c.skex = make([]byte, len(b))
	copy(c.skex, b)
	if e != nil {
		return nil, e
	}
	k, e := parseKexInit(c, b[1:])
	Log(6, "%v", k)
	if e != nil {
		return nil, e
	}
	e = dh(c, k, &C)
	if e != nil {
		return nil, e
	}

	client := &Client{ssh: c, efun: C.ErrorFun}
	for C.PasswordFun != nil {
		pass, err := C.PasswordFun()
		if err != nil {
			return nil, err
		}
		if password(c, C.User, pass) {
			break
		}
	}
	startClientLoop(client)
	return client, nil
}
