package as2

import (
	"slices"
	"testing"
)

func TestSplitMultipart(t *testing.T) {
	tests := []struct {
		name string
		body string
		want []string
	}{
		{
			name: "crlf",
			body: "preamble\r\n--b\r\nA: 1\r\n\r\none\r\n--b\r\n\r\ntwo\r\n--b--\r\n",
			want: []string{"A: 1\r\n\r\none", "\r\ntwo"},
		},
		{
			name: "bare lf",
			body: "--b\nA: 1\n\none\n--b\n\ntwo\n--b--\n",
			want: []string{"A: 1\n\none", "\ntwo"},
		},
		{
			name: "longer boundary and mid-line text are not delimiters",
			body: "--b\r\n\r\nx --b y\r\n--bb\r\n--b\r\n\r\ntwo\r\n--b--",
			want: []string{"\r\nx --b y\r\n--bb", "\r\ntwo"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := splitMultipart([]byte(tt.body), "b")
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, len(parts))
			for i, p := range parts {
				got[i] = string(p)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	if _, err := splitMultipart([]byte("--b\r\n\r\none\r\n"), "b"); err == nil {
		t.Error("missing closing delimiter: want error")
	}
}

func TestUnquoteID(t *testing.T) {
	for in, want := range map[string]string{
		`ACME`:          "ACME",
		` "My Co" `:     "My Co",
		`"a \"b\" \\c"`: `a "b" \c`,
	} {
		if got := UnquoteID(in); got != want {
			t.Errorf("UnquoteID(%q) = %q, want %q", in, got, want)
		}
		if got := UnquoteID(quoteID(want)); got != want {
			t.Errorf("quote round trip of %q = %q", want, got)
		}
	}
}
