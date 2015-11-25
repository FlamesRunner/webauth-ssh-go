// log.go
package logger

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

//FATAL and PANIC are always thrown and logged

const (
	DEBUG   uint = 3
	INFO    uint = 2
	REQUEST uint = 2
	WARN    uint = 1
	ERROR   uint = 0
)

type Logger struct {
	initialized    bool
	LogVerbosity   uint
	LogTarget      interface{}
	messageChannel chan string
	fatalChannel   chan string
	panicChannel   chan string
}

func NewLogger(verbosity uint, target interface{}) *Logger {

	createdLogger := &Logger{initialized: false, LogVerbosity: verbosity, LogTarget: target,
		messageChannel: make(chan string, 20), fatalChannel: make(chan string), panicChannel: make(chan string)}
	createdLogger.init()

	return createdLogger
}

func (l *Logger) init() {

	if !l.initialized {
		log.SetFlags(log.Ldate | log.Lmicroseconds)

		go func() {
			if l.LogTarget != nil {

				if l.LogTarget.(string) == "syslog" {

					//TODO Implement syslog target

				} else {

					f, err := os.OpenFile(l.LogTarget.(string), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
					if err != nil {
						fmt.Printf("error opening log file: %v", err)
						os.Exit(1)
					}
					l.LogTarget = f

					log.SetOutput(f)

				}
			}

			for {
				select {

				case s := <-l.messageChannel:
					log.Println(s)
				case f := <-l.fatalChannel:
					log.Fatal(f)
				case p := <-l.panicChannel:
					log.Println(p)
					panic(p)
				}

			}

		}()

		l.initialized = true
	}
}

func requestProperties(r *http.Request) string {

	return stripPort(r.RemoteAddr)

}

func trace(level int) string {

	rawStackTrace := make([]byte, 1<<16)
	rawStackTrace = rawStackTrace[:runtime.Stack(rawStackTrace, false)]

	//log.Printf("%s", rawStackTrace)

	stackArray := strings.Split(string(rawStackTrace), "\n")

	//This section depends on the stack trace format provided by runtime.Stack

	stackLine := (level-1)*2 + 1
	stackArray = stackArray[stackLine : stackLine+2]
	r := regexp.MustCompile(`(.*)(\()(.*)(\))$`)
	rMatch := r.FindStringSubmatch(stackArray[0])

	callingFunction := rMatch[1]
	_, callingFile := filepath.Split(strings.Split(stackArray[1], " ")[0])
	//

	s := fmt.Sprintf("(%s %s)", callingFile, callingFunction)

	return s

	// This idiomatic solution is not precise with line numbers
	// For reasoning see https://golang.org/pkg/runtime/#Func.FileLine

	//	pc := make([]uintptr, 1)
	//	runtime.Callers(level, pc)
	//	f := runtime.FuncForPC(pc[0])
	//	completePath, line := f.FileLine(pc[0])
	//	_, file := filepath.Split(completePath)
	//	s := fmt.Sprintf("%s:%d %s", file, line, f.Name())

	//	return s

}

func (l *Logger) Requestf(format string, v ...interface{}) {
	if !(l.LogVerbosity >= REQUEST) {
		return
	}

	format = "REQUEST: " + format
	l.messageChannel <- fmt.Sprintf(format, v...)

}

func (l *Logger) Info(v ...interface{}) {

	if !(l.LogVerbosity >= INFO) {
		return
	}

	i := make([]interface{}, 1)

	if m, ok := v[0].(*http.Request); ok {
		i[0] = trace(3) + " " + requestProperties(m) + " INFO: "
		v = v[1:]
	} else {
		i[0] = trace(3) + " INFO: "
	}

	l.messageChannel <- fmt.Sprint(append(i, v...)...)

}

func (l *Logger) Infof(format string, v ...interface{}) {

	if !(l.LogVerbosity >= INFO) {
		return
	}

	if m, ok := v[0].(*http.Request); ok {
		format = trace(3) + " " + requestProperties(m) + " INFO: " + format
		v = v[1:]
	} else {
		format = trace(3) + " INFO: " + format
	}

	l.messageChannel <- fmt.Sprintf(format, v...)

}

func (l *Logger) Error(v ...interface{}) {

	if !(l.LogVerbosity >= ERROR) {
		return
	}

	i := make([]interface{}, 1)
	if m, ok := v[0].(*http.Request); ok {
		i[0] = trace(3) + " " + requestProperties(m) + " ERROR: "
		v = v[1:]
	} else {
		i[0] = trace(3) + " ERROR: "
	}
	l.messageChannel <- fmt.Sprint(append(i, v...)...)

}

func (l *Logger) Errorf(format string, v ...interface{}) {

	if !(l.LogVerbosity >= ERROR) {
		return
	}

	if m, ok := v[0].(*http.Request); ok {
		format = trace(3) + " " + requestProperties(m) + " ERROR: " + format
		v = v[1:]
	} else {
		format = trace(3) + " ERROR: " + format
	}

	l.messageChannel <- fmt.Sprintf(format, v...)

}

func (l *Logger) Warning(v ...interface{}) {

	if !(l.LogVerbosity >= WARN) {
		return
	}

	i := make([]interface{}, 1)
	if m, ok := v[0].(*http.Request); ok {

		i[0] = trace(3) + " " + requestProperties(m) + " WARNING: "
		v = v[1:]
	} else {
		i[0] = trace(3) + " WARNING: "
	}

	l.messageChannel <- fmt.Sprint(append(i, v...)...)

}

func (l *Logger) Warningf(format string, v ...interface{}) {

	if !(l.LogVerbosity >= WARN) {
		return
	}

	if m, ok := v[0].(*http.Request); ok {
		format = trace(3) + " " + requestProperties(m) + " WARNING: " + format
		v = v[1:]
	} else {
		format = trace(3) + " WARNING: " + format
	}
	l.messageChannel <- fmt.Sprintf(format, v...)

}

func (l *Logger) Debug(v ...interface{}) {

	if !(l.LogVerbosity >= DEBUG) {
		return
	}

	i := make([]interface{}, 1)
	if m, ok := v[0].(*http.Request); ok {
		i[0] = trace(3) + " " + requestProperties(m) + " DEBUG: "
		v = v[1:]
	} else {
		i[0] = trace(3) + " DEBUG: "
	}
	l.messageChannel <- fmt.Sprint(append(i, v...)...)

}

func (l *Logger) Debugf(format string, v ...interface{}) {

	if !(l.LogVerbosity >= DEBUG) {
		return
	}

	if m, ok := v[0].(*http.Request); ok {
		format = trace(3) + " " + requestProperties(m) + " DEBUG: " + format
		v = v[1:]
	} else {
		format = trace(3) + " DEBUG: " + format
	}
	l.messageChannel <- fmt.Sprintf(format, v...)

}

func (l *Logger) Fatal(v ...interface{}) {

	i := make([]interface{}, 1)

	if m, ok := v[0].(*http.Request); ok {
		i[0] = trace(3) + " " + requestProperties(m) + " FATAL: "
		v = v[1:]
	} else {
		i[0] = trace(3) + " FATAL: "
	}
	l.fatalChannel <- fmt.Sprint(append(i, v...)...)

}

func (l *Logger) Fatalf(format string, v ...interface{}) {

	if m, ok := v[0].(*http.Request); ok {
		format = trace(3) + " " + requestProperties(m) + " FATAL: " + format
		v = v[1:]
	} else {
		format = trace(3) + " FATAL: " + format
	}
	l.fatalChannel <- fmt.Sprintf(format, v...)

}

func (l *Logger) Panic(v ...interface{}) {

	i := make([]interface{}, 1)

	if m, ok := v[0].(*http.Request); ok {
		i[0] = trace(3) + " " + requestProperties(m) + " PANIC: "
		v = v[1:]
	} else {
		i[0] = trace(3) + " PANIC: "
	}

	if l.LogTarget != nil && l.LogTarget != os.Stderr {

		//Should print stack trace to log

		i[0] = i[0].(string) + "\n"
		s := make([]interface{}, 1)

		rawStackTrace := make([]byte, 1<<16)
		rawStackTrace = rawStackTrace[:runtime.Stack(rawStackTrace, true)]

		s[0] = string(rawStackTrace)

		l.panicChannel <- fmt.Sprint(append(append(i, v...), s)...)

	} else {
		l.panicChannel <- fmt.Sprint(append(i, v...)...)
	}

}

func (l *Logger) Panicf(format string, v ...interface{}) {

	if m, ok := v[0].(*http.Request); ok {
		format = trace(3) + " " + requestProperties(m) + " PANIC: " + format
		v = v[1:]
	} else {
		format = trace(3) + " PANIC: " + format
	}

	if l.LogTarget != nil && l.LogTarget != os.Stderr {

		//Should print stack trace to log

		format = format + "\n"

		rawStackTrace := make([]byte, 1<<16)
		rawStackTrace = rawStackTrace[:runtime.Stack(rawStackTrace, true)]

		format = format + string(rawStackTrace)

		l.panicChannel <- fmt.Sprintf(format, v...)

	} else {

		l.panicChannel <- fmt.Sprintf(format, v...)

	}

}

//Log package drop-in replacement functions
//Don't try tracing, simply pass to logging goroutine

func (l *Logger) Printf(format string, v ...interface{}) {

	l.messageChannel <- fmt.Sprintf(format, v...)

}

func (l *Logger) Print(v ...interface{}) {

	l.messageChannel <- fmt.Sprint(v...)

}

func (l *Logger) Println(v ...interface{}) {

	l.messageChannel <- fmt.Sprintln(v...)

}

// stripPort strips the port number if present
func stripPort(remoteAddr string) string {
	if i := strings.LastIndex(remoteAddr, ":"); i != -1 {
		return remoteAddr[:i]
	}
	return remoteAddr
}
