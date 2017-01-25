package hrproxy

import (
	elastic "gopkg.in/olivere/elastic.v5"
	"net/http"
	"time"
	"context"
	"fmt"
	"github.com/Sirupsen/logrus"
	"strings"
	"github.com/fatih/color"
	"strconv"
)

type esLogEntry struct {
	Timestamp     time.Time
	Method        string
	Host          string
	Referrer      string
	Path          string
	Query         string
	RemoteAddress string
	RemotePort    int
	UserAgent     string
	Code          int
	Elapsed       time.Duration
}

type ESLogger struct {
	flushTicker   *time.Ticker
	es            *elastic.Client
	upstream      chan *esLogEntry
	bufferSize    int
	flushInterval time.Duration
	buf           []*esLogEntry
	indexPrefix   string
	log           *logrus.Entry
}

func NewESLogger(es *elastic.Client, bufferSize int, flushInterval time.Duration, indexPrefix string) *ESLogger {
	prepareSize := bufferSize * 3
	sCh := make(chan *esLogEntry, prepareSize)
	ticker := time.NewTicker(flushInterval)
	esl := &ESLogger{
		flushTicker:      ticker,
		es:               es,
		upstream:         sCh,
		bufferSize:       bufferSize,
		flushInterval:    flushInterval,
		indexPrefix:      indexPrefix,
		buf:              make([]*esLogEntry, 0, bufferSize),
		log:              logrus.WithFields(logrus.Fields{
			"at":    "eslogger",
			"index": indexPrefix,
		}),
	}
	go esl.Start()
	return esl
}

func (e *ESLogger) Start() {
	nextFlush := time.Now()
	for {
		select {
		case now := <-e.flushTicker.C:
			if len(e.buf) == 0 {
				continue
			}
			if now.After(nextFlush) {
				e.doFlush()
			}
			break
		case l := <-e.upstream:
			if l == nil {
				return
			}
			e.printAccessLog(l)
			if len(e.buf) == cap(e.buf) {
				e.doFlush()
			}
			e.buf = append(e.buf, l)
			if len(e.buf) == 1 { //first element
				nextFlush = time.Now().Add(e.flushInterval)
			}
			break
		}
	}
}

// Must be only called from Start method
func (e *ESLogger) doFlush() {
	index := fmt.Sprintf("hrproxy-%s-%s", e.indexPrefix, time.Now().Format("2006.01.02"))
	bulk := e.es.Bulk()
	for _, l := range e.buf {
		bulk.Add(
			elastic.NewBulkIndexRequest().
				Index(index).
				Type("hrproxy-access").
				Doc(l),
		)
	}
	br, err := bulk.Do(context.Background())
	if err != nil {
		e.log.Errorf("ElasticLog request error: %s", err)
	}
	if br.Errors {
		for _, item := range br.Items {
			for k, resp := range item {
				if resp.Error != nil {
					e.log.Errorf("ElasticLog error: %s %v", k, resp.Error)
				}
			}
		}
	}
	e.buf = e.buf[:0]
}

type colorPalate struct {
	statusColor *color.Color
}

var colorTable = []*colorPalate{
	1: {
		statusColor: color.New(),
	},
	2: {
		statusColor: color.New(color.FgBlue),
	},
	3: {
		statusColor: color.New(color.FgGreen),
	},
	4: {
		statusColor: color.New(color.FgYellow),
	},
	5: {
		statusColor: color.New(color.FgRed),
	},
}

func (e *ESLogger) printAccessLog(le *esLogEntry) {
	// Log slow request
	strTime := le.Timestamp.Format("15:04:05.999")
	palate := le.Code / 100
	if palate > 0 && palate <= 5 {
		p := colorTable[palate]
		fmt.Printf("%s %4s ", strTime, le.Method)
		p.statusColor.Printf("%3d ", le.Code)
		fmt.Printf("%15s %s %s\n", le.Host, le.RemoteAddress, le.Path)
	} else {
		fmt.Printf("%s %4s %3d %20s %s %s\n", strTime, le.Method, le.Code, le.Host, le.RemoteAddress, le.Path)
	}
}

func (e *ESLogger) Add(r *http.Request, statusCode int, begin, finish time.Time) {
	addrSplit := strings.Split(r.RemoteAddr, ":")
	var port int
	if remotePort, err := strconv.Atoi(addrSplit[1]); err == nil {
		port = remotePort
	}
	e.upstream <- &esLogEntry{
		Timestamp:     begin,
		Method:        r.Method,
		Host:          r.Host,
		Referrer:      r.Referer(),
		Path:          r.URL.Path,
		Query:         r.URL.RawQuery,
		RemoteAddress: addrSplit[0],
		RemotePort:    port,
		UserAgent:     strings.Join(r.Header["User-Agent"], ","),
		Elapsed:       finish.Sub(begin),
		Code:          statusCode,
	}
}
