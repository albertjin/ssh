include $(GOROOT)/src/Make.inc

TARG=bitbucket.org/taruti/ssh.go

GOFILES=\
	auth.go\
	client.go\
	connection.go\
	const.go\
	dh.go\
	dh_helper.go\
	transport.go\
	util.go\

include $(GOROOT)/src/Make.pkg
