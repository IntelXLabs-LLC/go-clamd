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

// Package main provides an example of how to use the go-clamd package.
// It demonstrates connecting to a ClamAV daemon and using various commands.
package main

import (
	_ "bytes"
	"fmt"
	"github.com/IntelXLabs-LLC/go-clamd"
)

// main is the entry point for the example program.
// It demonstrates how to create a connection to the ClamAV daemon
// and use various commands like Ping, Stats, and Reload.
func main() {
	fmt.Println("Made with <3 DutchCoders")

	// Create a new connection to the ClamAV daemon
	c := clamd.NewClamd("/tmp/clamd.socket")
	_ = c

	/*
		// Example of scanning the EICAR test virus from a stream
		reader := bytes.NewReader(clamd.EICAR)
		response, err := c.ScanStream(reader)

		for s := range response {
			fmt.Printf("%v %v\n", s, err)
		}

		// Example of scanning a directory
		response, err = c.ScanFile(".")

		for s := range response {
			fmt.Printf("%v %v\n", s, err)
		}

		// Example of getting the ClamAV version
		response, err = c.Version()

		for s := range response {
			fmt.Printf("%v %v\n", s, err)
		}
	*/

	// Example of pinging the ClamAV daemon
	err := c.Ping()
	fmt.Printf("Ping: %v\n", err)

	// Example of getting statistics from the ClamAV daemon
	stats, err := c.Stats()
	fmt.Printf("%v %v\n", stats, err)

	// Example of reloading the virus databases
	err = c.Reload()
	fmt.Printf("Reload: %v\n", err)

	// Example of shutting down the ClamAV daemon (commented out to prevent actual shutdown)
	// response, err = c.Shutdown()
	// fmt.Println(response)
}
