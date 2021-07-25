package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/net/proxy"
	"golang.org/x/sync/errgroup"

	"github.com/cirocosta/drwho/pkg/who"
)

type command struct {
	concurrency uint
	fpath       string
	proxy       string
	verbose     bool

	client *who.Client
}

func (c *command) Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drwho",
		Args:  cobra.ArbitraryArgs,
		Short: "batch whois resolver",
		RunE:  c.RunE,
	}

	cmd.Flags().StringVarP(&c.proxy, "proxy", "x",
		"", "socks5 proxy to send queries through")

	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v",
		false, "whether we should be verbose or not")

	cmd.Flags().StringVarP(&c.fpath, "file", "f",
		"", "location of a file containing ipv4 addresses to resolve")
	_ = cmd.MarkFlagFilename("file")

	cmd.Flags().UintVar(&c.concurrency, "concurrency",
		8, "maximum number of whois queries to have "+
			"in-flight at the same time")

	return cmd
}

func (c *command) RunE(_ *cobra.Command, argv []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.initClient(); err != nil {
		return fmt.Errorf("init client: %w", err)
	}

	addresses, err := c.gatherAddressesToResolve(argv)
	if err != nil {
		return fmt.Errorf("gather addrs to resolve: %w", err)
	}

	resolvedC := make(chan *who.Response)
	addressesC := make(chan string)

	var g *errgroup.Group
	g, ctx = errgroup.WithContext(ctx)

	concurrency := min(int(c.concurrency), len(addresses))
	for i := 0; i <= concurrency; i++ {
		g.Go(func() error {
			return c.resolve(ctx, addressesC, resolvedC)
		})
	}

	printC := make(chan error)
	go c.printResults(resolvedC, printC)

	for _, addr := range addresses {
		addressesC <- addr
	}
	close(addressesC)

	if err := g.Wait(); err != nil {
		return fmt.Errorf("wait: %w", err)
	}
	close(resolvedC)

	return <-printC
}

func (c *command) resolve(
	ctx context.Context, addressesC chan string, resC chan *who.Response,
) error {
	for address := range addressesC {
		res, err := c.client.Whois(ctx, address)
		if err != nil {
			return fmt.Errorf("whois '%s': %w", address, err)
		}

		res.Addr = address
		resC <- res
	}

	return nil
}

func (c *command) initClient() error {
	opts := []who.ClientOption{}
	if c.verbose {
		opts = append(opts, who.WithVerbose(true))
	}

	if c.proxy != "" {
		dialer, err := proxy.SOCKS5("tcp", c.proxy, nil, nil)
		if err != nil {
			return fmt.Errorf("socks5 '%s': %w", c.proxy, err)
		}

		contextDialer, ok := dialer.(proxy.ContextDialer)
		if !ok {
			return fmt.Errorf("can't cast proxy dialer " +
				"to proxy context dialer")
		}

		opts = append(opts, who.WithContextDialer(contextDialer))
	}

	c.client = who.NewClient(opts...)
	return nil
}

// nolint:forbidigo
func (c *command) printResults(resC chan *who.Response, printC chan error) {
	fmt.Printf("%s,%s,%s,%s\n", "ADDR", "ORG", "COUNTRY", "RECURSE ERR")
	for res := range resC {
		fmt.Printf("%s,%s,%s,%t\n",
			res.Addr,
			res.Name(),
			res.Country,
			res.RecurseError != nil,
		)
	}

	printC <- nil
}

func (c *command) gatherAddressesToResolve(argv []string) ([]string, error) {
	addresses := append([]string{}, argv...)

	if c.fpath != "" {
		addressesFromFile, err := c.readAddressesFromFile()
		if err != nil {
			return nil, fmt.Errorf(
				"read addresses from file: %w", err)
		}

		addresses = append(addresses, addressesFromFile...)
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("at least one address must be " +
			"specified, either via positional args or a file.")
	}

	return addresses, nil
}

func (c *command) readAddressesFromFile() ([]string, error) {
	var r io.Reader

	if c.fpath == "-" {
		r = os.Stdin
	} else {
		file, err := os.Open(c.fpath)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to open file at %s: %w", c.fpath, err)
		}
		defer file.Close()

		r = file
	}

	addrs := []string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		addrs = append(addrs, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed scanning lines: %w", err)
	}

	return addrs, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}

	return b
}
