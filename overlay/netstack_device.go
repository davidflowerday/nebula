package overlay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/socks"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var udpTimeout = 5 * time.Minute

type netstackDev struct {
	cidr      *net.IPNet
	prefix    netip.Prefix
	mtu       int
	Routes    []Route
	routeTree *cidr.Tree4
	log       *logrus.Logger

	stack *stack.Stack
	ep    *channel.Endpoint
	nicID tcpip.NICID
}

func newNetstackDevice(l *logrus.Logger, cidr *net.IPNet, defaultMTU int, routes []Route) (*netstackDev, error) {
	routeTree, err := makeRouteTree(l, routes, false)
	if err != nil {
		return nil, err
	}

	prefix, err := iputil.ToNetIpPrefix(*cidr)
	if err != nil {
		return nil, err
	}

	dev := &netstackDev{
		cidr:      cidr,
		prefix:    prefix,
		mtu:       defaultMTU,
		Routes:    routes,
		routeTree: routeTree,
		log:       l,

		nicID: tcpip.NICID(1),
	}

	return dev, nil
}

func (d *netstackDev) Activate() error {
	d.stack = stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			//arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			//icmp.NewProtocol4,
		},
	})

	// Create virtual NIC on netstack to represent the Nebula interface
	d.ep = channel.New(128, uint32(d.mtu), "")
	if err := d.stack.CreateNIC(d.nicID, d.ep); err != nil {
		return errors.New(err.String())
	}

	// Set virtual NIC IP address
	protocolAddr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.Address(d.cidr.IP.To4()).WithPrefix(),
	}
	if err := d.stack.AddProtocolAddress(d.nicID, protocolAddr, stack.AddressProperties{}); err != nil {
		d.log.WithFields(logrus.Fields{"error": err, "protocolAddr": protocolAddr}).Fatal("AddProtocolAddress error")
	}

	// Enable promiscuous mode so that we get callbacks for all traffic on the
	// interface rather than just traffic destined for the bound IP
	d.stack.SetPromiscuousMode(d.nicID, true)

	// Enable address spoofing so that we can appear as any address that Nebula
	// attempts to connect to (e.g. external IPs routed to us via unsafe_route)
	d.stack.SetSpoofing(d.nicID, true)

	// Add the local Nebula subnet route
	awp := tcpip.AddressWithPrefix{Address: tcpip.Address(string(d.prefix.Masked().Addr().AsSlice())), PrefixLen: d.prefix.Bits()}
	d.stack.AddRoute(tcpip.Route{Destination: awp.Subnet(), NIC: d.nicID})

	// Add static routes based on Nebula unsafe_routes configuration
	for _, r := range d.Routes {
		if r.Via == nil {
			// We don't allow route MTUs so only install routes with a via
			continue
		}

		prefix, err := iputil.ToNetIpPrefix(*r.Cidr)
		if err != nil {
			d.log.WithError(err).WithFields(logrus.Fields{"subnet": r.Cidr, "via": r.Via}).Warn("Failed converting CIDR to prefix")
			continue
		}
		awp := tcpip.AddressWithPrefix{Address: tcpip.Address(string(prefix.Masked().Addr().AsSlice())), PrefixLen: prefix.Bits()}
		d.stack.AddRoute(tcpip.Route{NIC: d.nicID, Destination: awp.Subnet(), Gateway: tcpip.Address(r.Via.ToIP())})

		d.log.WithFields(logrus.Fields{"subnet": r.Cidr, "via": r.Via}).Info("Added subnet route")
	}

	// Set up protocol handler for incoming TCP connections so they can be proxied locally
	fwdTCP := tcp.NewForwarder(d.stack, 0, 5, d.handleTCP)
	d.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwdTCP.HandlePacket)

	// Set up protocol handler for incoming UDP connections so they can be proxied locally
	fwdUDP := udp.NewForwarder(d.stack, d.handleUDP)
	d.stack.SetTransportProtocolHandler(udp.ProtocolNumber, fwdUDP.HandlePacket)

	// Set up SOCKS server to forward connections to Nebula
	stackDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		netaddr := netip.MustParseAddrPort(address)

		addr := tcpip.FullAddress{
			NIC:  d.nicID,
			Addr: tcpip.Address(netaddr.Addr().AsSlice()),
			Port: netaddr.Port(),
		}

		return gonet.DialContextTCP(ctx, d.stack, addr, ipv4.ProtocolNumber)
	}
	s := socks.New(d.log, stackDialer)
	go func() {
		listener, err := net.Listen("tcp", ":1080")
		if err != nil {
			panic(err)
		}
		s.Serve(listener)
	}()

	return nil
}

func (d *netstackDev) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := d.routeTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

func (d *netstackDev) Cidr() *net.IPNet {
	return d.cidr
}

func (d *netstackDev) Name() string {
	return "netstack"
}

func (d *netstackDev) Read(buf []byte) (int, error) {
	pkt := d.ep.ReadContext(context.Background())

	b := pkt.Buffer()
	n := copy(buf, b.Flatten())

	pkt.DecRef()

	return n, nil
}

func (d *netstackDev) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	// NewPacketBuffer takes ownership of the data, so making a copy is
	// necessary
	data := make([]byte, len(buf))
	copy(data, buf)
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.NewWithData(data),
	})

	var ipver tcpip.NetworkProtocolNumber
	switch header.IPVersion(buf) {
	case header.IPv4Version:
		ipver = ipv4.ProtocolNumber
	case header.IPv6Version:
		ipver = ipv6.ProtocolNumber
	default:
		return 0, fmt.Errorf("invalid IP version")
	}
	d.ep.InjectInbound(ipver, pb)

	return len(buf), nil
}

func (d *netstackDev) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for netstack")
}

func (d *netstackDev) Close() error {
	return nil // FIXME
}

// handleTCP handles an incoming TCP connection (via Nebula) and proxies it to
// the destination port on the target host (or localhost if the Nebula VPN IP
// address is the target).
func (d *netstackDev) handleTCP(r *tcp.ForwarderRequest) {
	reqTuple := r.ID()

	log := logrus.WithFields(logrus.Fields{
		"localAddr":  reqTuple.LocalAddress,
		"localPort":  reqTuple.LocalPort,
		"remoteAddr": reqTuple.RemoteAddress,
		"remotePort": reqTuple.RemotePort,
	})

	log.Info("Starting TCP forwarding")

	var wq waiter.Queue
	ep, tcipiperr := r.CreateEndpoint(&wq)
	if tcipiperr != nil {
		log.WithField("error", tcipiperr).Error("CreateEndpoint error")
		r.Complete(true)
		return
	}
	r.Complete(false)

	ep.SocketOptions().SetKeepAlive(true)

	source := gonet.NewTCPConn(&wq, ep)
	defer source.Close()

	// Check if destination is the local Nebula IP and if so, forward to localhost instead
	var dstAddr string
	if bytes.Equal(d.cidr.IP, []byte(reqTuple.LocalAddress)) {
		dstAddr = fmt.Sprintf("127.0.0.1:%d", reqTuple.LocalPort)
	} else {
		dstAddr = fmt.Sprintf("%s:%d", reqTuple.LocalAddress.String(), reqTuple.LocalPort)
	}

	// Establish outbound TCP connection to the target host:port
	var dialer net.Dialer
	target, err := dialer.Dial("tcp", dstAddr)
	if err != nil {
		log.WithError(err).Error("Could not connect to target")
		return
	}
	defer target.Close()

	log.Infof("Connected to %s", dstAddr)

	// Start a goroutine to copy data in each direction for the proxy and then
	// wait for completion
	copy := func(dst io.Writer, src io.Reader, errC chan error) {
		_, err := io.Copy(dst, src)
		errC <- err
	}

	errors := make(chan error, 2)
	go copy(target, source, errors)
	go copy(source, target, errors)

	err = <-errors
	if err != nil {
		log.WithError(err).Error("Error during TCP forwarding")
	}

	log.Info("Ended TCP forwarding")
}

func (d *netstackDev) handleUDP(r *udp.ForwarderRequest) {
	reqTuple := r.ID()

	log := logrus.WithFields(logrus.Fields{
		"localAddr":  reqTuple.LocalAddress,
		"localPort":  reqTuple.LocalPort,
		"remoteAddr": reqTuple.RemoteAddress,
		"remotePort": reqTuple.RemotePort,
	})

	go func() {
		log.Info("Starting UDP forwarding")

		var wq waiter.Queue
		ep, tcipiperr := r.CreateEndpoint(&wq)
		if tcipiperr != nil {
			log.WithField("error", tcipiperr).Error("CreateEndpoint error")
			return
		}

		source := gonet.NewUDPConn(d.stack, &wq, ep)
		defer source.Close()

		// Check if destination is the local Nebula IP and if so, forward to localhost instead
		var dstAddr *net.UDPAddr
		var localAddr *net.UDPAddr
		if bytes.Equal(d.cidr.IP, []byte(reqTuple.LocalAddress)) {
			dstAddr = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: int(reqTuple.LocalPort)}
			localAddr = &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: 0}
		} else {
			dstAddr = &net.UDPAddr{IP: net.IP(reqTuple.LocalAddress), Port: int(reqTuple.LocalPort)}
			localAddr = &net.UDPAddr{IP: net.IP{0, 0, 0, 0}, Port: 0}
		}
		srcAddr := &net.UDPAddr{IP: net.IP(reqTuple.RemoteAddress), Port: int(reqTuple.RemotePort)}

		// Set up listener to receive UDP packets coming back from target
		dest, err := net.ListenUDP("udp", localAddr)
		if err != nil {
			log.WithError(err).Error("ListenUDP error")
			return
		}
		defer dest.Close()

		// Start a goroutine to copy data in each direction for the proxy and then
		// wait for completion
		copy := func(ctx context.Context, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, errC chan<- error) {
			buf := make([]byte, d.mtu)
			for {
				select {
				case <-ctx.Done():
					return
				default:
					var n int
					var err error
					n, _, err = src.ReadFrom(buf)
					if err == nil {
						_, err = dst.WriteTo(buf[:n], dstAddr)
					}

					// Return error code or nil to the error channel. Nil value
					// is used to signal activity.
					select {
					case errC <- err:
					default:
					}
				}
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		errors := make(chan error, 2)
		go copy(ctx, dest, dstAddr, source, errors)
		go copy(ctx, source, srcAddr, dest, errors)

		// Tear down the forwarding if there is no activity after a certain
		// period of time
		for keepGoing := true; keepGoing; {
			select {
			case err := <-errors:
				if err != nil {
					log.WithError(err).Error("Error during UDP forwarding")
					keepGoing = false
				}
				// If err is nil then this means some activity has occurred, so
				// reset the timeout timer by restarting the select
			case <-time.After(udpTimeout):
				log.Info("UDP forwarding timed out")
				keepGoing = false
			}
		}
		cancel()
		log.Info("Ended UDP forwarding")
	}()
}
