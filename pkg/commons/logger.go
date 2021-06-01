package commons

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"github.com/natefinch/lumberjack"
	log "github.com/sirupsen/logrus"
)

func InitLogrus(stdOut bool, isJason bool, fileName string, maxSize int, maxBackup int, maxAge int, compress bool, logLevel string) {
	// Log as JSON instead of the default ASCII formatter.
	if isJason {
		log.SetFormatter(&log.JSONFormatter{})
	} else {
		log.SetFormatter(&log.TextFormatter{})
	}

	logger := &lumberjack.Logger{
		Filename:   fileName,
		MaxSize:    maxSize, // megabytes
		MaxBackups: maxBackup,
		MaxAge:     maxAge,   //days
		Compress:   compress, // disabled by default
	}

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	// log.SetOutput(os.Stdout)
	if stdOut {
		mw := io.MultiWriter(os.Stdout, logger)
		log.SetOutput(mw)
	} else {
		mw := io.MultiWriter(logger)
		log.SetOutput(mw)
		// log.SetOutput(logger)
	}
	// log.SetOutput(logger)

	// Only log the warning severity or above.
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		log.Fatalf("failed to parse log level...")
	}
	log.SetLevel(level)
	// log.AddHook(ContextHook{})

}

var RE_stripFnPreamble = regexp.MustCompile(`^.*\.(.*)$`)

func LogrusFields() log.Fields {
	fnName := "<unknown>"
	fileName := "<unknown>"
	// fileName := "<unknown>"
	// Skip this function, and fetch the PC and file for its parent
	pc, fileName, line, ok := runtime.Caller(1)
	if ok {
		fnName = RE_stripFnPreamble.ReplaceAllString(runtime.FuncForPC(pc).Name(), "$1")
		fileName = filepath.Base(fileName)
	}

	f := log.Fields{
		"fileName": fmt.Sprintf(fileName+"(%v)", line),
		"funcName": fnName,
	}
	return f
}

func LogrusHTTPFields(url string, reqBody, resBody []byte) log.Fields {
	fnName := "<unknown>"
	fileName := "<unknown>"
	lURL := ""
	var lReqBody string
	var lResBody string
	// fileName := "<unknown>"
	// Skip this function, and fetch the PC and file for its parent
	pc, fileName, line, ok := runtime.Caller(1)
	if ok {
		fnName = RE_stripFnPreamble.ReplaceAllString(runtime.FuncForPC(pc).Name(), "$1")
		fileName = filepath.Base(fileName)
	}

	if len(url) > 0 {
		lURL = url
	}
	if len(reqBody) > 0 {
		lReqBody = string(reqBody)
	}
	if len(resBody) > 0 {
		lResBody = string(resBody)
	}

	f := log.Fields{
		"fileName": fmt.Sprintf(fileName+"(%v)", line),
		"funcName": fnName,
		"url":      lURL,
		"reqBody":  lReqBody,
		"resBody":  lResBody,
	}
	return f
}

func LogrusHTTPFieldsV2(url string, ip string, reqBody, resBody []byte) log.Fields {
	fnName := "<unknown>"
	fileName := "<unknown>"
	lURL := ""
	var lReqBody string
	var lResBody string
	// fileName := "<unknown>"
	// Skip this function, and fetch the PC and file for its parent
	pc, fileName, line, ok := runtime.Caller(1)
	if ok {
		fnName = RE_stripFnPreamble.ReplaceAllString(runtime.FuncForPC(pc).Name(), "$1")
		fileName = filepath.Base(fileName)
	}

	if len(url) > 0 {
		lURL = url
	}
	if len(reqBody) > 0 {
		lReqBody = string(reqBody)
	}
	if len(resBody) > 0 {
		lResBody = string(resBody)
	}

	f := log.Fields{
		"fileName": fmt.Sprintf(fileName+"(%v)", line),
		"funcName": fnName,
		"url":      lURL,
		"clientIP": ip,
		"reqBody":  lReqBody,
		"resBody":  lResBody,
	}
	return f
}

func LogrusKafkaFields(failure, topic string, partition int32, offset int64, value []byte) log.Fields {
	fnName := "<unknown>"
	fileName := "<unknown>"

	// Skip this function, and fetch the PC and file for its parent
	pc, fileName, line, ok := runtime.Caller(1)
	if ok {
		fnName = RE_stripFnPreamble.ReplaceAllString(runtime.FuncForPC(pc).Name(), "$1")
		fileName = filepath.Base(fileName)
	}

	f := log.Fields{
		"fileName":  fmt.Sprintf(fileName+"(%v)", line),
		"funcName":  fnName,
		"kafka_msg": failure,
		"topic":     topic,
		"partition": partition,
		"offset":    offset,
		"value":     string(value),
	}
	return f
}
