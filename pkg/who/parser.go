package who

import (
	"bufio"
	"fmt"
	"strings"
)

type Response struct {
	// Whois indicates what is a follow-up WHOIS server that should be
	// reached to in order to find out information about this addr.
	//
	Whois string
}

// Parse evaluates the body of a WHOIS request, parsing such information in a
// format that we can better deal with.
//
func Parse(body string) (*Response, error) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	response := &Response{}

	for scanner.Scan() {
		line := scanner.Text()

		if response.Whois == "" {
			ref, err := findReferral(line)
			if err != nil {
				return nil, fmt.Errorf("find referral: %w", err)
			}
			if ref != "" {
				response.Whois = ref
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed scanning lines: %w", err)
	}

	return response, nil
}

// findReferral looks for entries that indicate that we should follow up with a
// request to a more specialized whois server.
//
func findReferral(line string) (string, error) {
	prefixes := []string{
		"registrar whois server:",
		"whois:",
		"referralserver:",
	}

	line = strings.ToLower(line)

	for _, prefix := range prefixes {
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return "", fmt.Errorf("expected to split '%s' "+
				"in two parts, but got %d",
				line, len(parts),
			)
		}

		return removeScheme(strings.TrimSpace(parts[1])), nil
	}

	return "", nil
}

// removeScheme removes the scheme of an address (<scheme>://<something> ==>
// <something>) _if_ there is one.
//
func removeScheme(addr string) string {
	addrParts := strings.SplitN(addr, "://", 2)
	if len(addrParts) == 2 {
		addr = addrParts[1]
	}

	return addr
}
