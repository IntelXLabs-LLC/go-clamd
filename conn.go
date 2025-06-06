/*
Open Source Initiative OSI - The MIT License (MIT):Licensing

The MIT License (MIT)
Copyright (c) 2013 DutchCoders <http://github.com/dutchcoders/>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// Package clamd provides a client for the ClamAV daemon (clamd).
// This file contains the connection handling code for communicating with the ClamAV daemon.
package clamd

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CHUNK_SIZE is the size of the chunks used when sending data to the ClamAV daemon.
const CHUNK_SIZE = 1024

// TCP_TIMEOUT is the timeout for TCP connections to the ClamAV daemon.
const TCP_TIMEOUT = time.Second * 2

// resultRegex is a regular expression used to parse the response from the ClamAV daemon.
// It extracts the path, description, virus hash, virus size, and status from the response.
var resultRegex = regexp.MustCompile(
	`^(?P<path>[^:]+): ((?P<desc>[^:]+)(\((?P<virhash>([^:]+)):(?P<virsize>\d+)\))? )?(?P<status>FOUND|ERROR|OK)$`,
)

// CLAMDConn represents a connection to the ClamAV daemon.
// It embeds net.Conn to provide the basic connection functionality.
type CLAMDConn struct {
	net.Conn
}

// sendCommand sends a command to the ClamAV daemon.
// It formats the command with a newline and sends it over the connection.
// Returns an error if any occurred.
func (conn *CLAMDConn) sendCommand(command string) error {
	commandBytes := []byte(fmt.Sprintf("n%s\n", command))

	_, err := conn.Write(commandBytes)
	return err
}

// sendEOF sends an EOF (end of file) marker to the ClamAV daemon.
// This is used to terminate a stream of data.
// Returns an error if any occurred.
func (conn *CLAMDConn) sendEOF() error {
	_, err := conn.Write([]byte{0, 0, 0, 0})
	return err
}

// sendChunk sends a chunk of data to the ClamAV daemon.
// It prepends the data with a 4-byte length header in network byte order.
// Returns an error if any occurred.
func (conn *CLAMDConn) sendChunk(data []byte) error {
	var buf [4]byte
	lenData := len(data)
	buf[0] = byte(lenData >> 24)
	buf[1] = byte(lenData >> 16)
	buf[2] = byte(lenData >> 8)
	buf[3] = byte(lenData >> 0)

	a := buf

	b := make([]byte, len(a))
	for i := range a {
		b[i] = a[i]
	}

	conn.Write(b)

	_, err := conn.Write(data)
	return err
}

// readResponse reads the response from the ClamAV daemon.
// It returns a channel of ScanResults, a WaitGroup that will be done when the response is complete,
// and an error if any occurred.
func (c *CLAMDConn) readResponse() (chan *ScanResult, *sync.WaitGroup, error) {
	var wg sync.WaitGroup

	wg.Add(1)
	reader := bufio.NewReader(c)
	ch := make(chan *ScanResult)

	go func() {
		defer func() {
			close(ch)
			wg.Done()
		}()

		for {
			line, err := reader.ReadString('\n')
			if err == io.EOF {
				return
			}

			if err != nil {
				return
			}

			line = strings.TrimRight(line, " \t\r\n")
			ch <- parseResult(line)
		}
	}()

	return ch, &wg, nil
}

// parseResult parses a line of response from the ClamAV daemon into a ScanResult.
// It uses the resultRegex to extract the path, description, virus hash, virus size, and status.
// Returns a ScanResult containing the parsed information.
func parseResult(line string) *ScanResult {
	res := &ScanResult{}
	res.Raw = line

	matches := resultRegex.FindStringSubmatch(line)
	if len(matches) == 0 {
		res.Description = "Regex had no matches"
		res.Status = RES_PARSE_ERROR
		return res
	}

	for i, name := range resultRegex.SubexpNames() {
		switch name {
		case "path":
			res.Path = matches[i]
		case "desc":
			res.Description = matches[i]
		case "virhash":
			res.Hash = matches[i]
		case "virsize":
			i, err := strconv.Atoi(matches[i])
			if err == nil {
				res.Size = i
			}
		case "status":
			switch matches[i] {
			case RES_OK:
			case RES_FOUND:
			case RES_ERROR:
				break
			default:
				res.Description = "Invalid status field: " + matches[i]
				res.Status = RES_PARSE_ERROR
				return res
			}
			res.Status = matches[i]
		}
	}

	return res
}

// newCLAMDTcpConn creates a new TCP connection to the ClamAV daemon.
// It dials the specified address with a timeout.
// Returns a CLAMDConn and an error if any occurred.
func newCLAMDTcpConn(address string) (*CLAMDConn, error) {
	conn, err := net.DialTimeout("tcp", address, TCP_TIMEOUT)

	if err != nil {
		if nerr, isOk := err.(net.Error); isOk && nerr.Timeout() {
			return nil, nerr
		}

		return nil, err
	}

	return &CLAMDConn{Conn: conn}, err
}

// newCLAMDUnixConn creates a new Unix socket connection to the ClamAV daemon.
// It dials the specified Unix socket path.
// Returns a CLAMDConn and an error if any occurred.
func newCLAMDUnixConn(address string) (*CLAMDConn, error) {
	conn, err := net.Dial("unix", address)
	if err != nil {
		return nil, err
	}

	return &CLAMDConn{Conn: conn}, err
}
