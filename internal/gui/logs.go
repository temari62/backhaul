package gui

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// LogLine is one entry shown in the app's activity panel.
type LogLine struct {
	Seq   int    `json:"seq"`
	Time  string `json:"time"`
	Level string `json:"level"`
	Text  string `json:"text"`
}

// LogBuffer is an slog.Handler keeping the last N records in memory (for the
// UI) and mirroring them to an optional writer (the log file).
type LogBuffer struct {
	mu    sync.Mutex
	lines []LogLine
	max   int
	seq   int
	file  io.Writer
	level slog.Level
}

// NewLogBuffer keeps up to max lines.
func NewLogBuffer(max int, file io.Writer, level slog.Level) *LogBuffer {
	return &LogBuffer{max: max, file: file, level: level}
}

func (b *LogBuffer) Enabled(_ context.Context, l slog.Level) bool { return l >= b.level }

func (b *LogBuffer) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	sb.WriteString(r.Message)
	write := func(a slog.Attr) bool {
		if a.Key == "" {
			return true
		}
		fmt.Fprintf(&sb, "  %s=%v", a.Key, a.Value.Resolve())
		return true
	}
	r.Attrs(write)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.seq++
	l := LogLine{Seq: b.seq, Time: r.Time.Format("15:04:05"), Level: r.Level.String(), Text: sb.String()}
	b.lines = append(b.lines, l)
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
	if b.file != nil {
		fmt.Fprintf(b.file, "%s %-5s %s\n", r.Time.Format(time.RFC3339), l.Level, l.Text)
	}
	return nil
}

// WithAttrs returns a view that writes into the same buffer.
func (b *LogBuffer) WithAttrs(as []slog.Attr) slog.Handler {
	return &sharedHandler{root: b, attrs: as}
}

func (b *LogBuffer) WithGroup(string) slog.Handler { return b }

// After returns lines with Seq > after.
func (b *LogBuffer) After(after int) []LogLine {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := []LogLine{}
	for _, l := range b.lines {
		if l.Seq > after {
			out = append(out, l)
		}
	}
	return out
}

// sharedHandler is a WithAttrs view onto a root LogBuffer.
type sharedHandler struct {
	root  *LogBuffer
	attrs []slog.Attr
}

func (s *sharedHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return s.root.Enabled(ctx, l)
}
func (s *sharedHandler) Handle(ctx context.Context, r slog.Record) error {
	r2 := r.Clone()
	r2.AddAttrs(s.attrs...)
	return s.root.Handle(ctx, r2)
}
func (s *sharedHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &sharedHandler{root: s.root, attrs: append(append([]slog.Attr{}, s.attrs...), as...)}
}
func (s *sharedHandler) WithGroup(string) slog.Handler { return s }
