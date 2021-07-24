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

	// Org is the name of the entity responsible for this address.
	//
	Org string
}

// Parse evaluates the body of a WHOIS request, parsing such information in a
// format that we can better deal with.
//
func Parse(body string) (*Response, error) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	response := &Response{}

	for scanner.Scan() {
		line := scanner.Text()

		var err error
		if response.Org == "" {
			response.Org, err = findOrg(line)
			if err != nil {
				return nil, fmt.Errorf("find org: %w", err)
			}
		}

		if response.Whois == "" {
			response.Whois, err = findReferral(line)
			if err != nil {
				return nil, fmt.Errorf("find ref: %w", err)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed scanning lines: %w", err)
	}

	return response, nil
}

func findWithPrefixes(line string, prefixes []string) (string, error) {
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

		return strings.TrimSpace(parts[1]), nil
	}

	return "", nil
}

func findOrg(line string) (string, error) {
	prefixes := []string{
		"orgname:",
		"org-name:",
	}

	res, err := findWithPrefixes(line, prefixes)
	if err != nil {
		return "", fmt.Errorf("find with prefixes: %w", err)
	}

	return res, nil
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

	res, err := findWithPrefixes(line, prefixes)
	if err != nil {
		return "", fmt.Errorf("find with prefixes: %w", err)
	}

	return removeScheme(res), nil
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
