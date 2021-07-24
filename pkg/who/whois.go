package who

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// RootWHOISAddress is the address of the default WHOIS server that we
	// should always start our queries with.
	//
	DefaultRootWHOISAddress = "whois.iana.org"

	// DefaultTimeout is the default maximum amount of time to wait for a
	// request and response flow to take before bailing out, including the
	// dial time.
	//
	DefaultTimeout = 30 * time.Second

	// DefaultMaxRecurse indicates the maximum amount of times the client
	// is allowed to recurse by following WHOIS referrals.
	//
	DefaultMaxRecurse = 5

	DefaultToVerbose = false
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

func NewClient(opts ...ClientOption) *Client {
	client := &Client{
		contextDialer:    &net.Dialer{},
		maxRecurse:       DefaultMaxRecurse,
		rootWHOISAddress: DefaultRootWHOISAddress,
		timeout:          DefaultTimeout,
		verbose:          DefaultToVerbose,

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

	// conn, err := cfg.ContextDialer.DialContext(ctx, "tcp", addr)
	// if err != nil {
	// 	return nil, fmt.Errorf("dial ctx: %w", err)
	// }
}

// Whois runs WHOIS queries for a given addr (v4 or v6).
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
func (c *Client) Whois(ctx context.Context, addr string) (*Response, error) {
	server := c.rootWHOISAddress
	query := addr

	for i := 0; i < c.maxRecurse; i++ {
		c.logger.WithField("recurse", i).Debug("querying")

		resp, err := c.whois(ctx, server, []byte(query+"\r\n"))
		if err != nil {
			return nil, fmt.Errorf("whois: %w", err)
		}

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

	conn, err := c.contextDialer.DialContext(
		ctx, "tcp", addWHOISPortIfNotSet(server),
	)
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

	parsedBody, err := Parse(string(buffer))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}

	return parsedBody, nil
}

func addWHOISPortIfNotSet(addr string) string {
	if strings.HasSuffix(addr, ":43") {
		return addr
	}

	return addr + ":43"
}
