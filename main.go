package main

import (
	"github.com/fabian-z/webauth-ssh-go/logger"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gorilla/context"
	"github.com/gorilla/securecookie"
	"github.com/justinas/nosurf"
	"github.com/keep94/weblogs"
	"golang.org/x/crypto/ssh"
	"html/template"
	"math"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

var (
	log            *logger.Logger
	authRequestMap *AuthRequests
	secCookie      *securecookie.SecureCookie
	err            error
	templateStart  *template.Template
	templateAuth   *template.Template
)

const (
	hostName     = "demo.devhub.club"
	hostSSHPort  = 2222
	hostHTTPPort = 80
	sslEnabled   = false
	hostTLSPort  = 443
	sslKeyPath   = ""
	sslCertPath  = ""

	logLevel    = logger.DEBUG
	charBytes   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	charBits    = 6
	charMax     = 63 / charBits
	charMask    = 1<<charBits - 1
	tokenLength = 25
)

func init() {
	//Set second argument to log file
	log = logger.NewLogger(logLevel, nil)
}

func dontCache(w http.ResponseWriter, r *http.Request) {

	//Set necessary headers to avoid client and intermediate caching of response

	w.Header().Set("Expires", time.Unix(0, 0).Format(time.RFC1123))
	w.Header().Set("Last-Modified", time.Now().Format(time.RFC1123))
	w.Header().Set("Cache-Control", "private, no-store, max-age=0, no-cache, must-revalidate, post-check=0, pre-check=0")

	return
}

func setSecurityHeaders(rw http.ResponseWriter, r *http.Request) {

	if sslEnabled {
		rw.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	rw.Header().Set("X-Frame-Options", "DENY")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("X-XSS-Protection", "1; mode=block")

	//rw.Header().Set("Content-Security-Policy", "default-src 'none'; font-src 'self'; script-src 'self'; img-src 'self' data:; style-src 'self'; connect-src 'self';")

	return

}

func RandomString(n int) string {

	randInt, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		panic(err)
	}

	buf := make([]byte, n)

	for n, cache, remaining := n-1, randInt.Int64(), charMax; n >= 0; {
		if remaining == 0 {

			randInt, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
			if err != nil {
				panic(err)
			}

			cache, remaining = randInt.Int64(), charMax
		}
		if idx := int(cache & charMask); idx < len(charBytes) {
			buf[n] = charBytes[idx]
			n--
		}
		cache >>= charBits
		remaining--
	}

	return string(buf)
}

type AuthRequests struct {
	timestamps map[string]time.Time
	matches    map[string]string
	sync.Mutex
}

func init() {
	var hashKey = securecookie.GenerateRandomKey(64)
	var blockKey = securecookie.GenerateRandomKey(32)
	secCookie = securecookie.New(hashKey, blockKey)
	authRequestMap = &AuthRequests{make(map[string]time.Time), make(map[string]string), sync.Mutex{}}
}

func startHandler(w http.ResponseWriter, r *http.Request) {

	setSecurityHeaders(w, r)
	dontCache(w, r)

	//WuSign verification, worked perfectly
	//if r.URL.Path == "/devhub.club.html" {
	//w.Header().Set("Content-Type", "text/html")
	//w.WriteHeader(200)
	//fmt.Fprintf(w, "%s\n", "prorvAbpuYvE33xSQKcsHOziQLWadN2XXol8kL6wjtU=")
	//return
	//}

	data := struct {
		Token string
	}{
		nosurf.Token(r),
	}

	if err := templateStart.Execute(w, data); err != nil {
		log.Println(err)
	}
}

func authRequestHandler(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w, r)

	dontCache(w, r)
	randomToken := RandomString(25)

	if r.Method == "POST" {

		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Error parsing form", http.StatusBadRequest)
			return
		}

		if len(r.FormValue("pubkey")) == 0 {

			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

		pubKeyBytes := []byte(r.FormValue("pubkey"))
		pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)

		if err != nil {

			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "Invalid public key - <a href='/'>Try again</a>")

			log.Requestf("%s, Submission was: %s", err, r.FormValue("pubkey"))
			return
		}

		serializedValue := pubKey.Type() + " " + base64.StdEncoding.EncodeToString(pubKey.Marshal())

		value := map[string]string{
			"pubKey": serializedValue,
			"token":  randomToken,
		}

		if encoded, err := secCookie.Encode("pubKey", value); err == nil {

			cookie := &http.Cookie{
				Name:     "auth",
				Value:    encoded,
				Path:     "/",
				HttpOnly: true,
			}

			if sslEnabled {
				cookie.Secure = true
			}

			http.SetCookie(w, cookie)
		}

		data := struct {
			PubKey string
			Class  string
			Auth   string
		}{
			serializedValue,
			"failure",
			"Not yet authenticated - Try `ssh " + hostName + " -p " + strconv.Itoa(hostSSHPort) + " -l " + randomToken + "`!",
		}

		if err := templateAuth.Execute(w, data); err != nil {
			log.Println(err)
		}
		return

	} else {

		//Try to use cookie with GET

		if cookie, err := r.Cookie("auth"); err == nil {
			value := make(map[string]string)
			if err = secCookie.Decode("pubKey", cookie.Value, &value); err == nil {

				if len(value["pubKey"]) != 0 && len(value["token"]) == tokenLength {

					//Check shared map for authentication with given pubkey and generated token
					result := "failure"
					resultText := "Not yet authenticated - Try `ssh " + hostName + " -p " + strconv.Itoa(hostSSHPort) + "  -l " + value["token"] + "`!"

					authRequestMap.Lock()
					if verifiedPubKey, ok := authRequestMap.matches[value["token"]]; ok {

						if verifiedPubKey == value["pubKey"] {
							result = "success"
							resultText = "Auth successful!"
						} else {
							//Connection with matching token and differing pubkey was registered
							//Do nothing for now, for future hardening this may cause a session reset
						}

						//Cleanup in either case
						delete(authRequestMap.timestamps, value["token"])
						delete(authRequestMap.matches, value["token"])

					}
					authRequestMap.Unlock()

					data := struct {
						PubKey string
						Class  string
						Auth   string
					}{
						value["pubKey"],
						result,
						resultText,
					}

					if err := templateAuth.Execute(w, data); err != nil {
						log.Println(err)
					}
					return
				} else {
					http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
					return
				}

			} else {

				log.Println("error decoding cookie", err)
				if w != nil {
					cookie := &http.Cookie{
						Name:     "pubKey",
						Value:    "deleted",
						Path:     "/",
						HttpOnly: true,
						MaxAge:   -1,
					}

					if sslEnabled {
						cookie.Secure = true
					}

					http.SetCookie(w, cookie)
					http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
				}
				return
			}

		} else {

			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}

	}

}

func main() {

	//SSH goroutine

	go func() {
		config := ssh.ServerConfig{
			PublicKeyCallback: keyAuth,
		}
		config.AddHostKey(hostPrivateKeySigner)

		port := strconv.Itoa(hostSSHPort)

		socket, err := net.Listen("tcp", ":"+port)
		if err != nil {
			panic(err)
		}

		for {
			conn, err := socket.Accept()
			if err != nil {
				panic(err)
			}

			// From a standard TCP connection to an encrypted SSH connection
			sshConn, chans, reqs, err := ssh.NewServerConn(conn, &config)
			if err != nil {
				log.Println("Error accepting ssh connection: ", err)
				continue
			}

			log.Println("Connection from", sshConn.RemoteAddr())

			// Print incoming out-of-band Requests
			go handleRequests(reqs)
			// Accept all channels
			go handleChannels(chans)
		}
	}()

	//

	// Garbage collecting goroutine
	// For testing, a stop-the-world gc using mutexes shall be 'nuff
	go func() {

		for {
			authRequestMap.Lock()

			for k, v := range authRequestMap.timestamps {

				killtime := time.Now().Add(-5 * time.Minute)

				if v.Before(killtime) {
					log.Debugf("Garbage collected key %s, %v old", k, time.Now().Sub(v))
					delete(authRequestMap.timestamps, k)
					delete(authRequestMap.matches, k)
				}

			}

			authRequestMap.Unlock()
			time.Sleep(2 * time.Minute)
		}

	}()

	templateStart, err = template.New("index.html").ParseFiles("index.html")
	if err != nil {
		panic(err)
	}

	templateAuth, err = template.New("auth.html").ParseFiles("auth.html")
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/auth", authRequestHandler)
	http.HandleFunc("/", startHandler)

	weblogOptions := &weblogs.Options{

		Writer: nil,
		Logger: customLogger{},
	}

	csrfHandler := nosurf.New(http.DefaultServeMux)

	csrfHandler.SetBaseCookie(http.Cookie{HttpOnly: true, Secure: sslEnabled})

	handler := context.ClearHandler(weblogs.HandlerWithOptions(csrfHandler, weblogOptions))

	if sslEnabled {
		go http.ListenAndServe(":"+strconv.Itoa(hostHTTPPort), handler)
		http.ListenAndServeTLS(":"+strconv.Itoa(hostTLSPort), sslCertPath, sslKeyPath, handler)
	} else {
		http.ListenAndServe(":"+strconv.Itoa(hostHTTPPort), handler)
	}
}
