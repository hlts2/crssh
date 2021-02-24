package main_test

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

const (
	user = "user_1"
	host = "127.0.0.1"
	port = "2222"
	pass = "password"
)

func TestConnection(t *testing.T) {
	cfg := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
	}
	conn, err := ssh.Dial("tcp", host+":"+port, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	t.Logf("Successful connection to ssh server.  password: %s\n", pass)
}
