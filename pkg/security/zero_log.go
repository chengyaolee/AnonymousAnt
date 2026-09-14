package security

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"sync"
	"time"
)

// LogLevel represents the logging verbosity.
type LogLevel int

const (
	LevelOff LogLevel = iota
	LevelError
	LevelWarn
	LevelInfo
	LevelDebug
)

var (
	ipv4Regex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	ipv6Regex = regexp.MustCompile(`\b(?:[A-F0-9a-f]{1,4}:){7}[A-F0-9a-f]{1,4}\b`)

	defaultLogger = NewZeroLogger(LevelWarn, os.Stderr)
)

// ZeroLogger ensures absolute zero persistence to disk and sanitizes all output.
type ZeroLogger struct {
	mu     sync.Mutex
	level  LogLevel
	output io.Writer
}

// NewZeroLogger creates a ZeroLogger that outputs only to the provided writer (e.g. stderr).
// No files or databases are ever touched.
func NewZeroLogger(level LogLevel, out io.Writer) *ZeroLogger {
	if out == nil {
		out = io.Discard
	}
	return &ZeroLogger{
		level:  level,
		output: out,
	}
}

// SetLevel updates the log verbosity.
func (l *ZeroLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// Sanitize removes IP addresses and sensitive identifiers from a message string.
func Sanitize(msg string) string {
	msg = ipv4Regex.ReplaceAllString(msg, "[REDACTED_IP]")
	msg = ipv6Regex.ReplaceAllString(msg, "[REDACTED_IPV6]")
	return msg
}

func (l *ZeroLogger) log(lvl LogLevel, prefix, format string, args ...any) {
	if l.level < lvl {
		return
	}
	rawMsg := fmt.Sprintf(format, args...)
	safeMsg := Sanitize(rawMsg)
	timestamp := time.Now().UTC().Format("15:04:05.000")

	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.output, "[%s] [%s] %s\n", timestamp, prefix, safeMsg)
}

func (l *ZeroLogger) Error(format string, args ...any) {
	l.log(LevelError, "ERROR", format, args...)
}

func (l *ZeroLogger) Warn(format string, args ...any) {
	l.log(LevelWarn, "WARN", format, args...)
}

func (l *ZeroLogger) Info(format string, args ...any) {
	l.log(LevelInfo, "INFO", format, args...)
}

func (l *ZeroLogger) Debug(format string, args ...any) {
	l.log(LevelDebug, "DEBUG", format, args...)
}

// Package-level logging convenience functions.
func Error(format string, args ...any) { defaultLogger.Error(format, args...) }
func Warn(format string, args ...any)  { defaultLogger.Warn(format, args...) }
func Info(format string, args ...any)  { defaultLogger.Info(format, args...) }
func Debug(format string, args ...any) { defaultLogger.Debug(format, args...) }
func SetLogLevel(lvl LogLevel)         { defaultLogger.SetLevel(lvl) }
