package who

import (
	"bufio"
	"fmt"
	"strings"
)

type Response struct {
	Addr string

	// Whois indicates what is a follow-up WHOIS server that should be
	// reached to in order to find out information about this addr.
	//
	Whois string

	// Org is the name of the entity responsible for this address.
	//
	Org string

	// Country is the name of the country.
	//
	Country string

	// Netname
	//
	Netname string

	// Parent points at the parent WHOIS response that led to this.
	//
	Parent *Response

	RecurseError error
}

func (r *Response) Name() string {
	if r.Org != "" {
		return r.Org
	}

	if r.Netname != "" {
		return r.Netname
	}

	if r.Parent != nil {
		return r.Parent.Name()
	}

	return ""
}

// Parse evaluates the body of a WHOIS request, parsing such information in a
// format that we can better deal with.
//
func Parse(body string) (*Response, error) {
	scanner := bufio.NewScanner(strings.NewReader(body))
	response := &Response{}

	for scanner.Scan() {
		line := scanner.Text()

		if response.Org == "" {
			response.Org = findOrg(line)
		}

		if response.Netname == "" {
			response.Netname = findNetname(line)
		}

		if response.Whois == "" {
			response.Whois = findWhois(line)
		}

		if response.Country == "" {
			response.Country = findCountry(line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed scanning lines: %w", err)
	}

	return response, nil
}

func findNetname(line string) string {
	prefixes := []string{
		"netname:",
	}

	return findWithPrefixes(line, prefixes)
}

func findCountry(line string) string {
	prefixes := []string{
		"country:",
		"contact:country-code:",
	}

	return findWithPrefixes(line, prefixes)
}

func findOrg(line string) string {
	prefixes := []string{
		"orgname:",
		"org-name:",
		"contact:company:",
		"owner:",
	}

	return findWithPrefixes(line, prefixes)
}

// findWhois looks for entries that indicate that we should follow up with a
// request to a more specialized whois server.
//
func findWhois(line string) string {
	prefixes := []string{
		"registrar whois server:",
		"whois:",
		"referralserver:",
	}

	return removeScheme(findWithPrefixes(line, prefixes))
}

// findWithPrefixes searches a line for a value that starts with a prefix from
// the list of prefixes.
//
func findWithPrefixes(line string, prefixes []string) string {
	line = strings.ToLower(line)

	for _, prefix := range prefixes {
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		return strings.TrimSpace(line[len(prefix):])
	}

	return ""
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
