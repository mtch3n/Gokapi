//go:build test

package test

import (
	"fmt"
	"net"
	"os"
	"strconv"
)

// Test ports. `go test ./...` runs every package concurrently, so any two packages whose tests
// put a real listener on the wire (or that build the resulting URL into their own assertions) must
// never share a port - otherwise they race to bind it. Most packages that call
// testconfiguration.Create never do either of those things, so they stay on PortDefault, same as
// always. The ones that do get their own variable here, which is the single place that value is
// decided, so a package's test port can never drift out of sync with a URL asserted elsewhere.
//
// Every port is portBase plus its index plus GOKAPI_TEST_PORT_OFFSET. The offset moves the whole
// block at once, which lets several `go test` invocations run at the same time - run-tests.sh
// starts one per tag combination - without them binding each other's ports. Keep the offsets the
// callers pass further apart than this block is long.
const portBase = 53843

var (
	PortDefault        = testPort(0)
	PortSessionManager = testPort(1)
	PortApi            = testPort(2)
	PortFileupload     = testPort(3)
	PortApplyMaxExpiry = testPort(4)
	PortSelf           = testPort(5)
	PortSetup          = testPort(6)
	PortHelper         = testPort(7)
	PortRedisProvider  = testPort(8)
	PortRedisDatabase  = testPort(9)
	PortAddressInUse   = testPort(10)
)

// portOffset is added to every test port. It is read once, as the environment must not be able to
// move a port after a test has already bound it.
var portOffset = readPortOffset()

func readPortOffset() int {
	value := os.Getenv("GOKAPI_TEST_PORT_OFFSET")
	if value == "" {
		return 0
	}
	offset, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Errorf("invalid GOKAPI_TEST_PORT_OFFSET %s: %w", value, err))
	}
	return offset
}

// testPort returns the nth test port as a host:port pair, shifted by portOffset.
func testPort(index int) string {
	return "127.0.0.1:" + strconv.Itoa(portBase+index+portOffset)
}

// Url returns the base URL of a server bound to the given test port, without a trailing slash, for
// example "http://127.0.0.1:53843". Tests build their expected URLs from this, so an assertion can
// never drift away from the port the listener actually binds.
func Url(port string) string {
	return "http://" + port
}

// UrlLocalhost is Url with the host spelled "localhost". It reaches the same listener, but sends a
// different Host header, which some tests request the server with.
func UrlLocalhost(port string) string {
	return "http://localhost:" + PortNumber(port)
}

// PortNumber returns the port number of a test port, without the host.
func PortNumber(port string) string {
	_, number, err := net.SplitHostPort(port)
	if err != nil {
		panic(err)
	}
	return number
}
