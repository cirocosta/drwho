package who_test

import (
	"context"
	"net"
	"testing"

	"github.com/cirocosta/drwho/pkg/who"
)

type referralDialer struct{}

func (referralDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		buf := make([]byte, 256)
		_, _ = server.Read(buf)
		_, _ = server.Write([]byte("whois: whois.example.test\r\n"))
	}()
	return client, nil
}

func TestWhoisReturnsPartialResponseAtRecursionLimit(t *testing.T) {
	t.Parallel()

	client := who.NewClient(
		who.WithContextDialer(referralDialer{}),
		who.WithMaxRecurse(1),
	)

	response, err := client.Whois(context.Background(), "192.0.2.1")
	if err != nil {
		t.Fatalf("Whois() error = %v", err)
	}
	if response == nil {
		t.Fatal("Whois() response = nil, want partial response")
	}
	if response.RecurseError == nil {
		t.Fatal("Whois() RecurseError = nil, want recursion limit error")
	}
}
