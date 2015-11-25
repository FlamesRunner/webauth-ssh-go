package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"time"
)

var (
	hostPrivateKeySigner ssh.Signer
)

func init() {
	keyPath := "./host_key"
	if os.Getenv("HOST_KEY") != "" {
		keyPath = os.Getenv("HOST_KEY")
	}

	hostPrivateKey, err := ioutil.ReadFile(keyPath)
	if err != nil {
		panic(err)
	}

	hostPrivateKeySigner, err = ssh.ParsePrivateKey(hostPrivateKey)
	if err != nil {
		panic(err)
	}
}

func isValidToken(s string) bool {
	if len(s) != tokenLength {
		return false
	}
	for _, c := range s {
		if c > 127 {
			return false
		} else if !(c >= 65 && c <= 90) && !(c >= 97 && c <= 122) {
			return false
		}
	}
	return true
}

func keyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {

	log.Println(conn.RemoteAddr(), "authenticate with", key.Type(), "for user", conn.User())
	log.Println(base64.StdEncoding.EncodeToString(key.Marshal()))

	if isValidToken(conn.User()) {
		authRequestMap.Lock()
		authRequestMap.matches[conn.User()] = key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
		authRequestMap.timestamps[conn.User()] = time.Now()
		authRequestMap.Unlock()
		return nil, nil
	}

	//Causes "Permission denied (publickey)." for openssh. How can this bubble up to the user?
	return nil, errors.New("Invalid token/username.")
}

func handleRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		log.Printf("received out-of-band request: %+v", req)
	}
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if t := newChannel.ChannelType(); t != "session" {
			newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Printf("could not accept channel (%s)", err)
			continue
		}

		// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
		go func(in <-chan *ssh.Request) {
			for req := range in {
				//log.Printf("%v %s", req.Payload, req.Payload)
				ok := false
				switch req.Type {
				case "exec":

					ok = false
				case "shell":

					req.Reply(true, nil)
					channel.Write([]byte("Auth request received. "))

					channel.Close()
					channel.CloseWrite()
					return

				case "pty-req":
					// Responding 'ok' here will let the client
					// know we have a pty ready for input

					ok = true

				case "window-change":

					continue //no response
				}

				if !ok {
					log.Printf("declining %s request...", req.Type)
				}

				req.Reply(ok, nil)

			}
		}(requests)
	}
}
