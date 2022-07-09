package socks

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"
)

type (
	CommandType uint8
	SocksReply  uint8
)

const (
	version5 = 0x05

	authNone           = 0x00
	authNoneAcceptable = 0xFF

	addrIPv4       = 0x01
	addrDomainName = 0x03
	addrIPv6       = 0x04

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	replySuccess              = SocksReply(0x00)
	replyGeneralFailure       = SocksReply(0x01)
	replyHostUnreachable      = SocksReply(0x04)
	replyCmdNotSupported      = SocksReply(0x07)
	replyAddrTypeNotSupported = SocksReply(0x08)
)

type DialTCP func(ctx context.Context, network, address string) (net.Conn, error)

type socks5 struct {
	dialTCP DialTCP
	log     *logrus.Logger
}

func New(l *logrus.Logger, dialer DialTCP) *socks5 {
	return &socks5{
		dialTCP: dialer,
		log:     l,
	}
}

func (s *socks5) Serve(listener net.Listener) {
	s.log.Info("SOCKS server started")

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.log.WithError(err).Error("Failed accepting SOCKS request")
			continue
		}

		s.log.WithField("remoteAddr", conn.RemoteAddr()).Info("SOCKS connection accepted")

		// Handle connection in a separate goroutine
		go s.handle(conn)
	}
}

// handle handles an incoming SOCKS5 request on the supplied connection. This
// will block until the session is ended.
func (s *socks5) handle(conn net.Conn) {
	defer conn.Close()
	defer s.log.Info("SOCKS connection closed")

	err := s.handshake(conn)
	if err != nil {
		s.log.WithError(err).Error("SOCKS handshake error")
		return
	}

	cmd, target, err := s.readConnectionRequest(conn)
	if err != nil {
		s.log.WithError(err).Error("SOCKS connection request error")
		return
	}

	switch cmd {
	case cmdConnect:
		err = s.handleConnect(conn, target)
	case cmdBind:
		err = s.handleBind(conn, target)
	case cmdUDPAssociate:
		err = s.handleUDPAssociate(conn, target)
	default:
		s.sendError(conn, replyCmdNotSupported)
		s.log.WithField("cmd", cmd).Error("SOCKS unknown command received")
	}
	if err != nil {
		s.log.WithError(err).Error("Error while handling SOCKS command")
	}
}

// readConnectionRequest reads and parses the connection request from the client
// and returns a SOCKS command and target address.
func (s *socks5) readConnectionRequest(conn net.Conn) (cmd CommandType, target string, err error) {
	type connRequest struct {
		SocksVer uint8
		Command  CommandType
		_        uint8
		AddrType uint8
	}

	var req connRequest
	err = binary.Read(conn, binary.BigEndian, &req)
	if err != nil {
		s.sendError(conn, replyGeneralFailure)
		return 0, "", fmt.Errorf("reading connection request: %w", err)
	}
	if req.SocksVer != version5 {
		s.sendError(conn, replyGeneralFailure)
		return 0, "", fmt.Errorf("invalid SOCKS version in request: %d", req.SocksVer)
	}

	// Read rest of destination address based on address type
	var dstAddr string
	switch req.AddrType {
	case addrIPv4:
		var ip [4]byte
		_, err = io.ReadFull(conn, ip[:])
		if err != nil {
			s.sendError(conn, replyGeneralFailure)
			return 0, "", fmt.Errorf("reading IPv4 address: %w", err)
		}
		dstAddr = netip.AddrFrom4(ip).String()

	case addrDomainName:
		var nameLen [1]uint8
		_, err = io.ReadFull(conn, nameLen[:])
		if err != nil {
			s.sendError(conn, replyGeneralFailure)
			return 0, "", fmt.Errorf("reading dest name length: %w", err)
		}
		name := make([]uint8, nameLen[0])
		_, err = io.ReadFull(conn, name)
		if err != nil {
			s.sendError(conn, replyGeneralFailure)
			return 0, "", fmt.Errorf("reading dest name: %w", err)
		}
		dstAddr = string(name)

	case addrIPv6:
		s.sendError(conn, replyAddrTypeNotSupported)
		return 0, "", fmt.Errorf("IPv6 address unsupported")
	}

	// Read the destination port
	var dstPort uint16
	if err := binary.Read(conn, binary.BigEndian, &dstPort); err != nil {
		s.sendError(conn, replyGeneralFailure)
		return 0, "", fmt.Errorf("reading dest port: %w", err)
	}

	return req.Command, fmt.Sprintf("%s:%d", dstAddr, dstPort), nil
}

// handleConnect implements the Connect SOCKS5 command to establish a TCP
// connection to the target and then proxy data back and forth until the
// connection is closed.
func (s *socks5) handleConnect(conn net.Conn, target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dstConn, err := s.dialTCP(ctx, "tcp", target)
	if err != nil {
		s.sendError(conn, replyHostUnreachable)
		return fmt.Errorf("connecting to target %s: %w", target, err)
	}
	defer dstConn.Close()

	localAddr := netip.MustParseAddrPort(dstConn.LocalAddr().String())

	switch {
	case localAddr.Addr().Is4():
		type connResponse struct {
			SocksVer uint8
			Reply    SocksReply
			_        uint8
			AddrType uint8
			Addr     [4]byte
			BindPort uint16
		}
		rsp := connResponse{
			SocksVer: version5,
			Reply:    replySuccess,
			AddrType: addrIPv4,
			Addr:     localAddr.Addr().As4(),
			BindPort: localAddr.Port(),
		}
		binary.Write(conn, binary.BigEndian, rsp)
	case localAddr.Addr().Is6():
		type connResponse struct {
			SocksVer uint8
			Reply    SocksReply
			_        uint8
			AddrType uint8
			Addr     [16]byte
			BindPort uint16
		}
		rsp := connResponse{
			SocksVer: version5,
			Reply:    replySuccess,
			AddrType: addrIPv6,
			Addr:     localAddr.Addr().As16(),
			BindPort: localAddr.Port(),
		}
		binary.Write(conn, binary.BigEndian, rsp)
	default:
		s.sendError(conn, replyGeneralFailure)
		return fmt.Errorf("invalid local address")
	}

	copy := func(dst io.Writer, src io.Reader, errC chan<- error) {
		_, err := io.Copy(dst, src)
		errC <- err
	}

	errC := make(chan error, 2)
	go copy(dstConn, conn, errC)
	go copy(conn, dstConn, errC)

	for i := 0; i < 2; i++ {
		err = <-errC
		if err != nil {
			return fmt.Errorf("while proxying connection: %w", err)
		}
	}

	return err
}

func (s *socks5) handleBind(conn net.Conn, target string) error {
	s.sendError(conn, replyCmdNotSupported)
	return fmt.Errorf("not implemented")
}

func (s *socks5) handleUDPAssociate(conn net.Conn, target string) error {
	s.sendError(conn, replyCmdNotSupported)
	return fmt.Errorf("not implemented")
}

// handshake performs the initial handshake with the SOCKS client, ensuring the
// proper SOCKS version is used and that the appropriate authentication method
// is chosen. At this time the only authentication method is "no authentication".
func (s *socks5) handshake(conn net.Conn) error {
	type clientGreeting struct {
		SocksVer uint8
		NumAuth  uint8
	}
	var greet clientGreeting

	// Read the client greeting which includes the number of authentication
	// methods the client is sending, then read in the list of authentication
	// methods
	err := binary.Read(conn, binary.BigEndian, &greet)
	if err != nil {
		return fmt.Errorf("reading client greeting: %w", err)
	}
	if greet.SocksVer != version5 {
		return fmt.Errorf("unsupported SOCKS version: %d", greet.SocksVer)
	}
	auths := make([]uint8, greet.NumAuth)
	_, err = io.ReadFull(conn, auths)
	if err != nil {
		return fmt.Errorf("reading auth methods: %w", err)
	}

	// Check list of client authentication methods for the method we support
	found := false
	for _, auth := range auths {
		if auth == authNone {
			found = true
			break
		}
	}

	// Respond to the client with the chosen authentication moethod
	type serverChoice struct {
		SocksVer   uint8
		ChosenAuth uint8
	}
	if found {
		choice := serverChoice{SocksVer: version5, ChosenAuth: authNone}
		err = binary.Write(conn, binary.BigEndian, choice)
		if err != nil {
			return fmt.Errorf("sending server auth choice: %w", err)
		}
	} else {
		choice := serverChoice{SocksVer: version5, ChosenAuth: authNoneAcceptable}
		binary.Write(conn, binary.BigEndian, choice)
		return fmt.Errorf("no acceptable authentication method")
	}

	return nil
}

// sendError transmits a SOCKS error reply to the SOCKS client.
func (s *socks5) sendError(conn net.Conn, errCode SocksReply) error {
	type connResponse struct {
		SocksVer uint8
		Reply    SocksReply
		_        uint8
		AddrType uint8
		Addr     [4]byte
		BindPort uint16
	}
	rsp := connResponse{
		SocksVer: version5,
		Reply:    errCode,
		AddrType: addrIPv4,
		Addr:     [...]byte{0, 0, 0, 0},
		BindPort: 0,
	}
	return binary.Write(conn, binary.BigEndian, rsp)
}
