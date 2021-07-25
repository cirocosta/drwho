package who

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type VerboseConn struct {
	conn net.Conn
}

func (v *VerboseConn) Write(b []byte) (int, error) {
	fmt.Fprintf(os.Stderr, "WRITING FROM %s TO %s\n",
		v.conn.LocalAddr(), v.conn.RemoteAddr())

	v.printWithPadding(b)

	return v.conn.Write(b)
}

func (v *VerboseConn) Read(b []byte) (int, error) {
	n, err := v.conn.Read(b)

	fmt.Fprintf(os.Stderr, "READ FROM %s TO %s\n",
		v.conn.RemoteAddr(), v.conn.LocalAddr())

	v.printWithPadding(b)

	return n, err
}

func (v *VerboseConn) printWithPadding(b []byte) {
	body := make([]byte, len(b))
	copy(body, b)
	bodyStr := string(body)

	for _, line := range strings.Split(bodyStr, "\n") {
		fmt.Fprintln(os.Stderr, "\t"+line)
	}
}

func (v *VerboseConn) LocalAddr() net.Addr {
	return v.conn.LocalAddr()
}
func (v *VerboseConn) RemoteAddr() net.Addr {
	return v.conn.RemoteAddr()
}
func (v *VerboseConn) SetDeadline(t time.Time) error {
	return v.conn.SetDeadline(t)
}
func (v *VerboseConn) SetReadDeadline(t time.Time) error {
	return v.conn.SetReadDeadline(t)
}
func (v *VerboseConn) SetWriteDeadline(t time.Time) error {
	return v.conn.SetWriteDeadline(t)
}
