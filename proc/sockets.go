package proc

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// SocketProto identifies which /proc/net/* table a Socket came from.
type SocketProto string

const (
	ProtoTCP  SocketProto = "tcp"
	ProtoTCP6 SocketProto = "tcp6"
	ProtoUDP  SocketProto = "udp"
	ProtoUDP6 SocketProto = "udp6"
)

// tcpState maps the hex connection-state field in /proc/net/tcp[6]
// to its familiar name. UDP has no equivalent state machine — UDP
// entries always report as "" (not applicable).
var tcpState = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

// Socket is one entry from /proc/net/tcp[6] or /proc/net/udp[6],
// keyed by inode so it can be matched against a process's open file
// descriptors (which reference sockets as "socket:[inode]").
type Socket struct {
	Proto      SocketProto
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	State      string // TCP connection state name, "" for UDP
	Inode      uint64
}

// LocalEndpoint renders "addr:port" for the local side.
func (s Socket) LocalEndpoint() string {
	return net.JoinHostPort(s.LocalAddr, strconv.Itoa(int(s.LocalPort)))
}

// RemoteEndpoint renders "addr:port" for the remote side, or ""
// when there's no meaningful remote (e.g. a LISTEN socket).
func (s Socket) RemoteEndpoint() string {
	if s.RemoteAddr == "" || (s.RemoteAddr == "0.0.0.0" && s.RemotePort == 0) || (s.RemoteAddr == "::" && s.RemotePort == 0) {
		return ""
	}
	return net.JoinHostPort(s.RemoteAddr, strconv.Itoa(int(s.RemotePort)))
}

// ReadSockets parses every available /proc/net/{tcp,tcp6,udp,udp6}
// table into a single inode-keyed lookup. Reading /proc/net/* only
// requires the caller to be in the same network namespace as the
// target (not root, not CAP_NET_ADMIN) — this works unprivileged in
// the overwhelming majority of cases, matching this project's
// no-root-required design goal.
func ReadSockets() (map[uint64]Socket, error) {
	out := make(map[uint64]Socket)
	sources := []struct {
		path  string
		proto SocketProto
	}{
		{"/proc/net/tcp", ProtoTCP},
		{"/proc/net/tcp6", ProtoTCP6},
		{"/proc/net/udp", ProtoUDP},
		{"/proc/net/udp6", ProtoUDP6},
	}

	var lastErr error
	found := false
	for _, src := range sources {
		socks, err := parseNetTable(src.path, src.proto)
		if err != nil {
			lastErr = err
			continue // e.g. IPv6 disabled -> tcp6/udp6 absent; not fatal
		}
		found = true
		for _, s := range socks {
			out[s.Inode] = s
		}
	}

	if !found {
		return nil, fmt.Errorf("reading /proc/net sockets: %w", lastErr)
	}
	return out, nil
}

// parseNetTable parses one /proc/net/{tcp,tcp6,udp,udp6} file. Format
// is fixed-width whitespace-separated fields, header on line 1:
//
//	sl  local_address rem_address   st ... inode
//	0: 0100007F:1F90 00000000:0000 0A ... 12345
func parseNetTable(path string, proto SocketProto) ([]Socket, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var sockets []Socket
	scanner := bufio.NewScanner(f)
	scanner.Scan() // discard header line

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 {
			continue
		}
		local, localPort, ok1 := parseHexAddr(fields[1])
		remote, remotePort, ok2 := parseHexAddr(fields[2])
		if !ok1 || !ok2 {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		sockets = append(sockets, Socket{
			Proto:      proto,
			LocalAddr:  local,
			LocalPort:  localPort,
			RemoteAddr: remote,
			RemotePort: remotePort,
			State:      tcpState[fields[3]], // empty for UDP, which is fine/expected
			Inode:      inode,
		})
	}
	return sockets, scanner.Err()
}

// parseHexAddr decodes a /proc/net/tcp-style "ADDR:PORT" field, e.g.
// "0100007F:1F90" (127.0.0.1:8080) or its IPv6 equivalent. The
// address bytes are little-endian per 32-bit word, which is why this
// isn't just a plain hex.DecodeString — see kernel
// net/ipv4/tcp_ipv4.c's get_tcp4_sock for the on-disk format this
// mirrors.
func parseHexAddr(field string) (addr string, port uint16, ok bool) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return "", 0, false
	}
	addrHex, portHex := parts[0], parts[1]

	portN, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, false
	}

	raw, err := hex.DecodeString(addrHex)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}

	ip := make(net.IP, len(raw))
	// Each 4-byte group is stored in host (little-endian on x86) byte
	// order, so reverse each 4-byte word to get network byte order.
	for word := 0; word < len(raw); word += 4 {
		ip[word], ip[word+1], ip[word+2], ip[word+3] = raw[word+3], raw[word+2], raw[word+1], raw[word]
	}

	return ip.String(), uint16(portN), true
}

// ProcessSockets returns every Socket belonging to pid, found by
// cross-referencing its open file descriptors (which name sockets as
// "socket:[inode]") against the system-wide socket table. Requires
// FD read access to pid (same UID or root) in addition to /proc/net
// access; a permission error on the FD side yields an empty result
// rather than propagating, consistent with this package's
// degrade-gracefully-on-EACCES convention.
func ProcessSockets(pid int, allSockets map[uint64]Socket) []Socket {
	fds, err := ReadFDs(pid)
	if err != nil {
		return nil
	}

	var out []Socket
	for _, fd := range fds {
		if fd.Kind != FDSocket {
			continue
		}
		inode, ok := socketInodeFromTarget(fd.Target)
		if !ok {
			continue
		}
		if s, ok := allSockets[inode]; ok {
			out = append(out, s)
		}
	}
	return out
}

// socketInodeFromTarget extracts the inode from an fd target string
// like "socket:[123456]".
func socketInodeFromTarget(target string) (uint64, bool) {
	if !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
		return 0, false
	}
	inner := target[len("socket:[") : len(target)-1]
	n, err := strconv.ParseUint(inner, 10, 64)
	return n, err == nil
}
