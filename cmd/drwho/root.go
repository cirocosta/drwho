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
	// TODO
	concurrency uint
	fpath       string
	proxy       string
	verbose     bool
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
		10, "maximum number of whois queries to have "+
			"in-flight at the same time")

	return cmd
}

func (c *command) RunE(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addresses := append([]string{}, args...)

	if c.fpath != "" {
		addressesFromFile, err := c.readAddressesFromFile()
		if err != nil {
			return fmt.Errorf("read addresses from file: %w")
		}

		addresses = append(addresses, addressesFromFile...)
	}

	if len(addresses) == 0 {
		return fmt.Errorf("at least one address must be specified," +
			" either via positional args or a file.")
	}

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

	client := who.NewClient(opts...)
	if err := c.gatherInfo(ctx, client, addresses); err != nil {
		return fmt.Errorf("gather info: %w", err)
	}

	return nil
}

func (c *command) gatherInfo(
	ctx context.Context, client *who.Client, addresses []string,
) error {
	var g *errgroup.Group

	g, ctx = errgroup.WithContext(ctx)

	for _, addr := range addresses {
		addr := addr

		g.Go(func() error {
			res, err := client.Whois(ctx, addr)
			if err != nil {
				return fmt.Errorf("whois '%s': %w", addr, err)
			}

			fmt.Printf("%s,%s\n", addr, res.Org)
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	return nil
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
