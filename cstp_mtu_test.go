package openconnect

import "testing"

func TestCSTPBaseMTUFromSocketInfo(t *testing.T) {
	for _, testCase := range []struct {
		name               string
		pathMTU            uint32
		maximumSegmentSize int
		expected           uint32
	}{
		{name: "path MTU", pathMTU: 1500, maximumSegmentSize: 1448, expected: 1500},
		{name: "maximum segment fallback", maximumSegmentSize: 1448, expected: 1435},
		{name: "path MTU below IPv6 minimum", pathMTU: 1279, maximumSegmentSize: 1448, expected: 1435},
		{name: "invalid values", pathMTU: 65536, maximumSegmentSize: 13},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if actual := cstpBaseMTUFromSocketInfo(testCase.pathMTU, testCase.maximumSegmentSize); actual != testCase.expected {
				t.Fatalf("unexpected base MTU: got %d, want %d", actual, testCase.expected)
			}
		})
	}
}
