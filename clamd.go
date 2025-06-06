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
// It allows for virus scanning through the ClamAV engine using its TCP or Unix socket interface.
package clamd

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// Constants representing possible scan result statuses.
const (
	// RES_OK indicates that no virus was found.
	RES_OK = "OK"
	// RES_FOUND indicates that a virus was found.
	RES_FOUND = "FOUND"
	// RES_ERROR indicates that an error occurred during scanning.
	RES_ERROR = "ERROR"
	// RES_PARSE_ERROR indicates that an error occurred while parsing the scan result.
	RES_PARSE_ERROR = "PARSE ERROR"
)

// Clamd represents a connection to a ClamAV daemon.
type Clamd struct {
	// address is the socket address of the ClamAV daemon.
	address string
}

// Stats represents statistics about the ClamAV daemon.
type Stats struct {
	// Pools contains information about the thread pools.
	Pools string
	// State contains information about the daemon's state.
	State string
	// Threads contains information about the daemon's threads.
	Threads string
	// Memstats contains information about the daemon's memory usage.
	Memstats string
	// Queue contains information about the daemon's scan queue.
	Queue string
}

// ScanResult represents the result of a virus scan.
type ScanResult struct {
	// Raw is the raw response from the ClamAV daemon.
	Raw string
	// Description is the description of the virus if found.
	Description string
	// Path is the path of the scanned file.
	Path string
	// Hash is the hash of the virus if found.
	Hash string
	// Size is the size of the virus if found.
	Size int
	// Status is the status of the scan (OK, FOUND, ERROR, etc.).
	Status string
}

// EICAR is the EICAR test file, which is a standard test file used to verify that antivirus software is working correctly.
// It is not a virus, but it is detected as one by antivirus software.
var EICAR = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)

// newConnection creates a new connection to the ClamAV daemon.
// It parses the address to determine whether to use a TCP or Unix socket connection.
// Returns a CLAMDConn and an error if any occurred.
func (c *Clamd) newConnection() (conn *CLAMDConn, err error) {
	var u *url.URL

	if u, err = url.Parse(c.address); err != nil {
		return
	}

	switch u.Scheme {
	case "tcp":
		conn, err = newCLAMDTcpConn(u.Host)
	case "unix":
		conn, err = newCLAMDUnixConn(u.Path)
	default:
		conn, err = newCLAMDUnixConn(c.address)
	}

	return
}

// simpleCommand sends a command to the ClamAV daemon and returns a channel of ScanResults.
// The channel will be closed when the response is complete.
// Returns a channel of ScanResults and an error if any occurred.
func (c *Clamd) simpleCommand(command string) (chan *ScanResult, error) {
	conn, err := c.newConnection()
	if err != nil {
		return nil, err
	}

	err = conn.sendCommand(command)
	if err != nil {
		return nil, err
	}

	ch, wg, err := conn.readResponse()

	go func() {
		wg.Wait()
		conn.Close()
	}()

	return ch, err
}

// Ping checks the daemon's state.
// It sends a PING command to the ClamAV daemon and expects a PONG response.
// Returns nil if the daemon responds with PONG, or an error otherwise.
func (c *Clamd) Ping() error {
	ch, err := c.simpleCommand("PING")
	if err != nil {
		return err
	}

	select {
	case s := (<-ch):
		switch s.Raw {
		case "PONG":
			return nil
		default:
			return errors.New(fmt.Sprintf("Invalid response, got %s.", s))
		}
	}

	return nil
}

// Version returns the program and database versions of the ClamAV daemon.
// Returns a channel of ScanResults containing the version information and an error if any occurred.
func (c *Clamd) Version() (chan *ScanResult, error) {
	dataArrays, err := c.simpleCommand("VERSION")
	return dataArrays, err
}

// Stats returns statistics about the ClamAV daemon.
// It provides information about the scan queue, contents of scan queue, and memory usage.
// Returns a Stats struct and an error if any occurred.
func (c *Clamd) Stats() (*Stats, error) {
	ch, err := c.simpleCommand("STATS")
	if err != nil {
		return nil, err
	}

	stats := &Stats{}

	for s := range ch {
		if strings.HasPrefix(s.Raw, "POOLS") {
			stats.Pools = strings.Trim(s.Raw[6:], " ")
		} else if strings.HasPrefix(s.Raw, "STATE") {
			stats.State = s.Raw
		} else if strings.HasPrefix(s.Raw, "THREADS") {
			stats.Threads = s.Raw
		} else if strings.HasPrefix(s.Raw, "QUEUE") {
			stats.Queue = s.Raw
		} else if strings.HasPrefix(s.Raw, "MEMSTATS") {
			stats.Memstats = s.Raw
		} else if strings.HasPrefix(s.Raw, "END") {
		} else {
			//	return nil, errors.New(fmt.Sprintf("Unknown response, got %s.", s))
		}
	}

	return stats, nil
}

// Reload reloads the virus databases.
// It sends a RELOAD command to the ClamAV daemon and expects a RELOADING response.
// Returns nil if the daemon responds with RELOADING, or an error otherwise.
func (c *Clamd) Reload() error {
	ch, err := c.simpleCommand("RELOAD")
	if err != nil {
		return err
	}

	select {
	case s := (<-ch):
		switch s.Raw {
		case "RELOADING":
			return nil
		default:
			return errors.New(fmt.Sprintf("Invalid response, got %s.", s))
		}
	}

	return nil
}

// Shutdown instructs the ClamAV daemon to shutdown.
// Returns an error if any occurred.
func (c *Clamd) Shutdown() error {
	_, err := c.simpleCommand("SHUTDOWN")
	if err != nil {
		return err
	}

	return err
}

// ScanFile scans a file or directory (recursively) with archive support enabled.
// It requires a full path to the file or directory.
// Returns a channel of ScanResults and an error if any occurred.
func (c *Clamd) ScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("SCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

// RawScanFile scans a file or directory (recursively) with archive and special file support disabled.
// It requires a full path to the file or directory.
// Returns a channel of ScanResults and an error if any occurred.
func (c *Clamd) RawScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("RAWSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

// MultiScanFile scans a file in a standard way or scans a directory (recursively) using multiple threads.
// This makes the scanning faster on SMP machines.
// It requires a full path to the file or directory.
// Returns a channel of ScanResults and an error if any occurred.
func (c *Clamd) MultiScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("MULTISCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

// ContScanFile scans a file or directory (recursively) with archive support enabled.
// It doesn't stop the scanning when a virus is found.
// It requires a full path to the file or directory.
// Returns a channel of ScanResults and an error if any occurred.
func (c *Clamd) ContScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("CONTSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

// AllMatchScanFile scans a file or directory (recursively) with archive support enabled.
// It doesn't stop the scanning when a virus is found and reports all matches.
// It requires a full path to the file or directory.
// Returns a channel of ScanResults and an error if any occurred.
func (c *Clamd) AllMatchScanFile(path string) (chan *ScanResult, error) {
	command := fmt.Sprintf("ALLMATCHSCAN %s", path)
	ch, err := c.simpleCommand(command)
	return ch, err
}

// ScanStream scans a stream of data.
// The stream is sent to clamd in chunks, after INSTREAM, on the same socket on which the command was sent.
// This avoids the overhead of establishing new TCP connections and problems with NAT.
// The format of the chunk is: <length><data> where <length> is the size of the following data in
// bytes expressed as a 4 byte unsigned integer in network byte order and <data> is the actual chunk.
// Streaming is terminated by sending a zero-length chunk.
// Note: do not exceed StreamMaxLength as defined in clamd.conf, otherwise clamd will
// reply with INSTREAM size limit exceeded and close the connection.
// The abort channel can be used to abort the scan.
// Returns a channel of ScanResults and an error if any occurred.
func (c *Clamd) ScanStream(r io.Reader, abort chan bool) (chan *ScanResult, error) {
	conn, err := c.newConnection()
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			_, allowRunning := <-abort
			if !allowRunning {
				break
			}
		}
		conn.Close()
	}()

	conn.sendCommand("INSTREAM")

	for {
		buf := make([]byte, CHUNK_SIZE)

		nr, err := r.Read(buf)
		if nr > 0 {
			conn.sendChunk(buf[0:nr])
		}

		if err != nil {
			break
		}

	}

	err = conn.sendEOF()
	if err != nil {
		return nil, err
	}

	ch, wg, err := conn.readResponse()

	go func() {
		wg.Wait()
		conn.Close()
	}()

	return ch, nil
}

// NewClamd creates a new Clamd instance with the specified address.
// The address can be a TCP address (tcp://host:port) or a Unix socket path.
// Returns a new Clamd instance.
func NewClamd(address string) *Clamd {
	clamd := &Clamd{address: address}
	return clamd
}
