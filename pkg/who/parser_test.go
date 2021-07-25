package who_test

import (
	"testing"

	"github.com/cirocosta/drwho/pkg/who"

	"github.com/stretchr/testify/assert"
)

// nolint:funlen
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

		{
			name: "with 'ReferralServer' and 'OrgName'",
			body: `
# If you see inaccuracies in the results, please report at
OrgName:        RIPE Network Coordination Centre
ReferralServer:  whois://whois.ripe.net
`,
			expected: &who.Response{
				Whois: "whois.ripe.net",
				Org:   "ripe network coordination centre",
			},
		},

		{
			name: "with 'org-name'",
			body: `
organisation:   ORG-HOA1-RIPE
org-name:       Hetzner Online GmbH
`,
			expected: &who.Response{
				Org: "hetzner online gmbh",
			},
		},

		{
			name: "with 'contact:company'",
			body: `
contact:Class-Name:contact
contact:Name:Abuse Department
contact:Company:Joe's Datacenter, LLC
contact:Street-Address:1325 Tracy Ave.
contact:City:Kansas City
`,
			expected: &who.Response{
				Org: "joe's datacenter, llc",
			},
		},

		{
			name: "with 'netname:'",
			body: `
inetnum:        45.138.172.0 - 45.138.172.255
netname:        ROUTERHOSTING
remarks:        routerhosting.com
admin-c:        CONO
tech-c:         CONO
`,
			expected: &who.Response{
				Netname: "routerhosting",
			},
		},

		{
			name: "with 'owner:'",
			body: `
inetnum:     167.56.0.0/13
status:      allocated
aut-num:     N/A
owner:       Administracion Nacional de Telecomunicaciones
ownerid:     UY-ANTA-LACNIC
responsible: ANTEL URUGUAY
address:     Torre de las Telecomunicaciones, Guatemala, 1075, -
`,
			expected: &who.Response{
				Org: "administracion nacional de telecomunicaciones",
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
