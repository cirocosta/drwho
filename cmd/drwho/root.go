package main

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cirocosta/drwho/pkg/who"
)

type command struct {
	fpath   string
	verbose bool
}

func (c *command) Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drwho",
		Args:  cobra.ArbitraryArgs,
		Short: "batch whois resolver",
		RunE:  c.RunE,
	}
	cmd.Flags().BoolVarP(&c.verbose, "verbose", "v",
		false, "whether we should be verbose or not")

	cmd.Flags().StringVarP(&c.fpath, "file", "f",
		"", "location of a file containing ipv4 addresses to resolve")
	_ = cmd.MarkFlagFilename("file")

	return cmd
}

// nolint:forbidigo
func (c *command) RunE(_ *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	addresses := append([]string{}, args...)

	if len(addresses) == 0 {
		return fmt.Errorf("at least one address must be specified," +
			" either via positional args or a file.")
	}

	opts := []who.ClientOption{}
	if c.verbose {
		opts = append(opts, who.WithVerbose(true))
	}

	client := who.NewClient(opts...)

	for _, addr := range addresses {
		res, err := client.Whois(ctx, addr)
		if err != nil {
			return err
		}

		fmt.Println(res)
	}

	return nil
}
