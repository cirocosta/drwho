package who_test

import (
	"testing"

	"github.com/cirocosta/drwho/pkg/who"

	"github.com/stretchr/testify/assert"
)

func TestParse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name     string
		body     string
		expected *who.Response
		err      string
	}{
		{
			name:     "empty",
			body:     "",
			expected: &who.Response{},
		},
		{
			name: "with 'whois' referral",
			body: `
% IANA WHOIS server
% for more information on IANA, visit http://www.iana.org

whois:        whois.arin.net

source:       IANA `,
			expected: &who.Response{
				Whois: "whois.arin.net",
			},
		},

		{
			name: "with 'ReferralServer' referral",
			body: `
#
# foo

ReferralServer:  whois://whois.ripe.net
`,
			expected: &who.Response{
				Whois: "whois.ripe.net",
			},
		},
	} {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual, err := who.Parse(tc.body)
			if tc.err != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
