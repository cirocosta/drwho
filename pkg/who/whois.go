package who

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// RootWHOISAddress is the address of the default WHOIS server that we
	// should always start our queries with.
	//
	DefaultRootWHOISAddress = "whois.arin.net"

	// DefaultTimeout is the default maximum amount of time to wait for a
	// request and response flow to take before bailing out, including the
	// dial time.
	//
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRecurse indicates the maximum amount of times the client
	// is allowed to recurse by following WHOIS referrals.
	//
	DefaultMaxRecurse = 5

	// DefaultVerbose is the default configuration for the verbosity level.
	//
	DefaultVerbose = false
)

// Client provides the ability of retrieving WHOIS information starting from a
// root WHOIS server and recursing all the way to the most specialized whois
// server.
//
type Client struct {
	contextDialer    ContextDialer
	maxRecurse       int
	rootWHOISAddress string
	timeout          time.Duration
	verbose          bool

	logger *log.Entry
}

type ContextDialer interface {
	DialContext(
		ctx context.Context, network, addr string,
	) (net.Conn, error)
}

// WithRootWHOISAddress configures the root WHOIS server to start all queries
// from this client against.
//
func WithRootWHOISAddress(v string) func(*Client) {
	return func(c *Client) {
		c.rootWHOISAddress = v
	}
}

// WithContextDialer overrides the default context dialer. This is useful for,
// for instance, Switching to something like a SOCKS5 dialer which would allow
// one to make WHOIS requests over annonimity networks like Tor.
//
func WithContextDialer(v ContextDialer) func(*Client) {
	return func(c *Client) {
		c.contextDialer = v
	}
}

// WithRequestTimeout overrides the default timeout for the request and
// response flow.
//
func WithRequestTimeout(v time.Duration) func(*Client) {
	return func(c *Client) {
		c.timeout = v
	}
}

// WithMaxRecurse overrides the default maximum amount of recursions the client
// can perform.
//
func WithMaxRecurse(v int) func(*Client) {
	return func(c *Client) {
		c.maxRecurse = v
	}
}

// WithVerbose indicates whether we should be verbose or not.
//
func WithVerbose(v bool) func(*Client) {
	return func(c *Client) {
		c.verbose = v
	}
}

type ClientOption func(*Client)

// NewClient instantiates a new client responsible for handling recursive
// querying and parsing of WHOIS information.
//
// ps.: it is safe to invocate the same client's `.Whois` method concurrently -
// there is no shared context between multiple executions of it.
//
func NewClient(opts ...ClientOption) *Client {
	client := &Client{
		contextDialer:    &net.Dialer{},
		maxRecurse:       DefaultMaxRecurse,
		rootWHOISAddress: DefaultRootWHOISAddress,
		timeout:          DefaultTimeout,
		verbose:          DefaultVerbose,

		logger: log.WithFields(log.Fields{
			"component": "whois",
		}),
	}

	for _, opt := range opts {
		opt(client)
	}

	if client.verbose {
		log.SetLevel(log.DebugLevel)
	}

	return client
}

// Whois recursively submits WHOIS queries for a given addr (v4 or v6).
//
// It does so by first querying a root WHOIS server, and then based on its
// response, recursively querying other WHOIS servers for the information we
// care about.
//
// The initial query follows RFC3912:
//
//	client                           server at whois.nic.mil
//
//	open TCP   ---- (SYN) ------------------------------>
//	           <---- (SYN+ACK) -------------------------
//	send query ---- "Smith<CR><LF>" -------------------->
//	get answer <---- "Info about Smith<CR><LF>" ---------
//	           <---- "More info about Smith<CR><LF>" ----
//	close      <---- (FIN) ------------------------------
//	           ----- (FIN) ----------------------------->
//
// At this point, for instance, we might get a pointer to `whois.arin.net`, the
// server we should recurse to. If so, then we just proceed with the same[1]
// query to that server.
//
// [1]: note that some servers (like `arin`) expect the query to be prefixed
//      with `+ n` so that it's unambigous. from my understanding, that's _not_
//      a standard, so we must deal with it in a case-by-case basis.
//
func (c *Client) Whois(
	ctx context.Context, addrToQry string,
) (*Response, error) {
	var (
		server = c.rootWHOISAddress
		parent *Response
	)

	for i := 0; i < c.maxRecurse; i++ {
		c.logger.WithFields(log.Fields{
			"recurse": i,
			"addr":    addrToQry,
			"server":  server,
		}).Debug("querying")

		serverWithPort, err := addWHOISPortIfNotSet(server)
		if err != nil {
			return nil, fmt.Errorf(
				"add whois port if not set: %w", err)
		}

		query := c.buildQuery(serverWithPort, addrToQry)
		resp, err := c.whois(ctx, serverWithPort, query)
		if err != nil {
			err = fmt.Errorf("whois: %w", err)

			if i != 0 {
				parent.RecurseError = err
				return parent, nil
			}

			return nil, err
		}

		resp.Parent = parent
		parent = resp

		if resp.Whois == "" {
			return resp, nil
		}

		server = resp.Whois
		continue
	}

	return nil, nil
}

// whois connects against a `server` and submits a WHOIS `query` against it.
//
func (c *Client) whois(
	ctx context.Context, server string, query []byte,
) (*Response, error) {
	start := time.Now()

	conn, err := c.contextDialer.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, fmt.Errorf("dial context: %w", err)
	}
	defer conn.Close()

	elapsed := time.Since(start)
	_ = conn.SetWriteDeadline(time.Now().Add(c.timeout - elapsed))

	if _, err = conn.Write(query); err != nil {
		return nil, fmt.Errorf("write query '%s' to server '%s': %w",
			string(query), server, err)
	}

	elapsed = time.Since(start)
	_ = conn.SetReadDeadline(time.Now().Add(c.timeout - elapsed))

	buffer, err := ioutil.ReadAll(conn)
	if err != nil {
		return nil, fmt.Errorf("read response for query '%s' "+
			"on server '%s': %w", string(query), server, err)
	}

	if c.verbose {
		fmt.Fprintln(os.Stderr, string(buffer))
	}

	parsedBody, err := Parse(string(buffer))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return parsedBody, nil
}

// buildQuery prepares a WHOIS query.
//
func (c *Client) buildQuery(server, addr string) []byte {
	const crlf = "\r\n"

	if strings.HasPrefix(server, "whois.arin.net") {
		return []byte("n + " + addr + crlf)
	}

	return []byte(addr + crlf)
}

func addWHOISPortIfNotSet(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		addrErr := &net.AddrError{}
		if !errors.As(err, &addrErr) {
			return "", fmt.Errorf("splithostport '%s': "+
				"not addrerror: %w", addr, err)
		}

		if !strings.Contains(addrErr.Err, "missing port") {
			return "", fmt.Errorf("splithostport '%s': "+
				"err is not missing port: %w", addr, err)
		}

		return addr + ":43", nil
	}

	return net.JoinHostPort(host, port), nil
}
