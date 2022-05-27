package main

import (
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/socks"
)

func main() {
	dialer := net.Dialer{}
	s := socks.New(logrus.New(), dialer.DialContext)
	listener, err := net.Listen("tcp", ":1080")
	if err != nil {
		panic(err)
	}
	s.Serve(listener)
}
