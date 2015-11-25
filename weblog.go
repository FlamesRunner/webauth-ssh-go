package main

import (
	"github.com/keep94/weblogs"
	"github.com/keep94/weblogs/loggers"
	"io"
	"net/http"
	"time"
)

type loggerBase struct {
}

func (l loggerBase) NewSnapshot(r *http.Request) weblogs.Snapshot {
	return loggers.NewSnapshot(r)
}

func (l loggerBase) NewCapture(w http.ResponseWriter) weblogs.Capture {
	return &loggers.Capture{ResponseWriter: w}
}

type customLogger struct {
	loggerBase
}

func (l customLogger) Log(w io.Writer, record *weblogs.LogRecord) {

	s := record.R.(*loggers.Snapshot)
	c := record.W.(*loggers.Capture)

	log.Requestf("%d %s \"%s %s %s\" %d %d%s",
		c.Status(),
		loggers.StripPort(s.RemoteAddr),
		s.Method,
		s.URL.RequestURI(),
		s.Proto,
		c.Size(),
		record.Duration/time.Millisecond,
		record.Extra)
}
