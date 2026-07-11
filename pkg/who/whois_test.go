package who_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cirocosta/drwho/pkg/who"
)

func TestAddWHOISPortIfNotSet(t *testing.T) {
	t.Parallel()

	const defaultAddress = "foo:43"

	for _, tc := range []struct {
		name     string
		input    string
		expected string
		err      string
	}{
		{
			name:     "no port",
			input:    "foo",
			expected: "foo:43",
		},

		{
			name:     "with std port",
			input:    defaultAddress,
			expected: defaultAddress,
		},

		{
			name:     "with non-std port",
			input:    "foo:1043",
			expected: "foo:1043",
		},
		{
			name:     "IPv6 without port",
			input:    "2001:db8::1",
			expected: "[2001:db8::1]:43",
		},
		{
			name:  "malformed addr",
			input: "1:23:23",
			err:   "too many",
		},
	} {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			actual, err := who.AddWHOISPortIfNotSet(tc.input)
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
