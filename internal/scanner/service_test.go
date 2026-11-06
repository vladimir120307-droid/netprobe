package scanner

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// scriptDials swaps the dialer for in-memory connections, so no test here opens
// a socket. Each dial is served by the next function, then dials start failing.
func scriptDials(t *testing.T, servers ...func(net.Conn)) {
	t.Helper()
	original := dialConn
	t.Cleanup(func() { dialConn = original })

	dialConn = func(network, addr string, timeout time.Duration) (net.Conn, error) {
		if len(servers) == 0 {
			return nil, errors.New("connection refused")
		}
		serve := servers[0]
		servers = servers[1:]

		client, server := net.Pipe()
		go func() {
			defer server.Close()
			serve(server)
		}()
		return client, nil
	}
}

// hangUp stands in for a service that never answers: the client's read fails,
// which takes the same path as a read timeout without waiting for one.
func hangUp(net.Conn) {}

// greet sends text as soon as the client connects.
func greet(text string) func(net.Conn) {
	return func(c net.Conn) { c.Write([]byte(text)) }
}

// reply waits for the client's request, then sends text.
func reply(text string) func(net.Conn) {
	return func(c net.Conn) {
		c.Read(make([]byte, 256))
		c.Write([]byte(text))
	}
}

func TestDetectService(t *testing.T) {
	const httpOK = "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n"

	cases := []struct {
		name        string
		port        int
		servers     []func(net.Conn)
		wantService string
		wantVersion string
	}{
		{"ssh greets first", 22,
			[]func(net.Conn){greet("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n")}, "ssh", "OpenSSH_8.9p1"},
		{"http needs a real request", 80,
			[]func(net.Conn){hangUp, hangUp, reply(httpOK)}, "http", "nginx/1.24.0"},
		{"https keeps its port name", 443,
			[]func(net.Conn){hangUp, hangUp, reply(httpOK)}, "https", "nginx/1.24.0"},
		{"http on an unknown port", 12345,
			[]func(net.Conn){hangUp, hangUp, reply(httpOK)}, "http", "nginx/1.24.0"},
		{"http answers the empty line", 8000,
			[]func(net.Conn){hangUp, reply("HTTP/1.1 400 Bad Request\r\nServer: Apache\r\n\r\n")}, "http-alt", "Apache"},
		{"non-http answer to the http request", 5432,
			[]func(net.Conn){hangUp, hangUp, reply("EFATAL\x00invalid length of startup packet\x00")}, "postgresql", ""},
		{"mysql greeting", 3306,
			[]func(net.Conn){greet("\x4a\x00\x00\x00\x0a8.0.35\x00\x08\x00\x00\x00mysql_native_password\x00")}, "mysql", "MySQL 8.0.35"},
		{"control characters are cleaned from the version", 12345,
			[]func(net.Conn){greet("Proxy\x07 server\x00 ready\r\n")}, "", "Proxy server ready"},
		{"nothing answers", 6379, nil, "redis", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			scriptDials(t, c.servers...)
			service, version := DetectService("example.test", c.port, "tcp")
			if service != c.wantService || version != c.wantVersion {
				t.Errorf("got (%q, %q), want (%q, %q)", service, version, c.wantService, c.wantVersion)
			}
		})
	}
}

func TestProbesAreSentWithCRLF(t *testing.T) {
	got := make(chan string, 1)
	capture := func(answer string) func(net.Conn) {
		return func(c net.Conn) {
			buf := make([]byte, 256)
			n, _ := c.Read(buf)
			got <- string(buf[:n])
			c.Write([]byte(answer))
		}
	}

	scriptDials(t, capture("HTTP/1.0 200 OK\r\n\r\n"))
	if _, err := ProbeService("example.test", 80, time.Second); err != nil {
		t.Fatal(err)
	}
	if req, want := <-got, "GET / HTTP/1.0\r\nHost: example.test\r\n\r\n"; req != want {
		t.Errorf("HTTP probe sent %q, want %q", req, want)
	}

	scriptDials(t, hangUp, capture("hello\r\n"))
	banner, err := TCPBannerGrab("example.test", 9999, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if req := <-got; req != "\r\n" {
		t.Errorf("generic probe sent %q", req)
	}
	if banner != "hello\r\n" {
		t.Errorf("banner should come back unchanged, got %q", banner)
	}
}

func TestParseVersion(t *testing.T) {
	cases := []struct {
		name   string
		banner string
		port   int
		want   string
	}{
		{"ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", 22, "OpenSSH_8.9p1"},
		{"ssh with a second line", "SSH-2.0-OpenSSH_8.9p1\r\nInvalid SSH identification string.\r\n", 22, "OpenSSH_8.9p1"},
		{"ftp crlf", "220 ProFTPD 1.3.6\r\n", 21, "ProFTPD 1.3.6"},
		{"ftp lf", "220 ProFTPD 1.3.6\n230 more\n", 21, "ProFTPD 1.3.6"},
		{"smtp", "220 mail.example.com ESMTP Postfix\r\n", 25, "ESMTP Postfix"},
		{"smtp with a second line", "220-mail.example.com ESMTP Exim\r\n220 ready\r\n", 25, "ESMTP Exim"},
		{"http crlf", "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n", 80, "nginx/1.24.0"},
		{"http lf", "HTTP/1.1 200 OK\nServer: nginx/1.24.0\n\n", 80, "nginx/1.24.0"},
		{"http without a server header", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 80, ""},
		{"mysql", "\x4a\x00\x00\x00\x0a8.0.35\x00\x08", 3306, "MySQL 8.0.35"},
		{"mysql error packet", "\x4a\x00\x00\x00\xffj\x04Host is blocked", 3306, "\x4a\x00\x00\x00\xffj\x04Host is blocked"},
		{"redis", "-ERR unknown command\r\n", 6379, "Redis"},
		{"generic crlf", "hello there\r\nsecond\r\n", 9999, "hello there"},
		{"generic lf", "hello there\nsecond\n", 9999, "hello there"},
		{"generic cr", "hello there\rsecond", 9999, "hello there"},
		{"long line", strings.Repeat("x", 80), 9999, strings.Repeat("x", 60) + "..."},
	}

	for _, c := range cases {
		if got := parseVersion(c.banner, c.port); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDetectServiceFromBanner(t *testing.T) {
	cases := map[string]string{
		"SSH-2.0-OpenSSH_8.9p1":                     "ssh",
		"220 ProFTPD 1.3.6":                         "ftp",
		"220 mail.example.com ESMTP Postfix":        "smtp",
		"HTTP/1.1 200 OK\r\n\r\nour ftp and imap":   "http",
		"\x4a\x00\x00\x00\x0a8.0.35\x00mysql_x\x00": "mysql",
		"something unknown":                         "",
	}
	for banner, want := range cases {
		if got := detectServiceFromBanner(banner); got != want {
			t.Errorf("%q: got %q, want %q", banner, got, want)
		}
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner(" a\r\nb\tc\x00d\x7fe ")
	if want := "a  b cde"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
