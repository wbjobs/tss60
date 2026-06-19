package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/color"
	"gopkg.in/yaml.v3"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target bpf -type event bpf openat_trace.c

const (
	eventQueueSize   = 16384
	alertQueueSize   = 4096
	printFlushBytes  = 64 * 1024
	printFlushPeriod = 50 * time.Millisecond
	statsLogPeriod   = 30 * time.Second
	alertFlushPeriod = 1 * time.Second
)

type parsedEvent struct {
	Pid    uint32
	Comm   string
	Path   string
	Mode   string
	ModeCl *color.Color
	CommCl *color.Color
	Ts     string
}

type Rule struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	Comm        string `yaml:"comm"`
	Path        string `yaml:"path"`
	PathContains string `yaml:"path_contains"`
	Mode        string `yaml:"mode"`
	Severity    string `yaml:"severity"`
	Message     string `yaml:"message"`
}

type Config struct {
	AlertLog string `yaml:"alert_log"`
	Rules    []Rule `yaml:"rules"`
}

type Alert struct {
	Rule    Rule
	Event   parsedEvent
	Ts      string
}

var colorList = []*color.Color{
	color.New(color.FgCyan),
	color.New(color.FgGreen),
	color.New(color.FgYellow),
	color.New(color.FgMagenta),
	color.New(color.FgBlue),
	color.New(color.FgRed),
	color.New(color.FgHiCyan),
	color.New(color.FgHiGreen),
	color.New(color.FgHiYellow),
	color.New(color.FgHiMagenta),
	color.New(color.FgHiBlue),
	color.New(color.FgHiRed),
}

var commColorMap = make(map[string]*color.Color)
var colorCounter int

func getCommColor(comm string) *color.Color {
	if c, ok := commColorMap[comm]; ok {
		return c
	}
	c := colorList[colorCounter%len(colorList)]
	colorCounter++
	commColorMap[comm] = c
	return c
}

func decodeOpenFlags(flags int32) string {
	switch {
	case flags&syscall.O_RDWR != 0:
		return "RDWR"
	case flags&syscall.O_WRONLY != 0:
		return "WR"
	default:
		return "RD"
	}
}

func modeColor(mode string) *color.Color {
	switch mode {
	case "RD":
		return color.New(color.FgGreen)
	case "WR":
		return color.New(color.FgRed)
	case "RDWR":
		return color.New(color.FgYellow)
	default:
		return color.New(color.Reset)
	}
}

type stats struct {
	consumed     uint64
	dropped      uint64
	printDropped uint64
	alerts       uint64
	alertDropped uint64
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	return &cfg, nil
}

func matchRule(rule Rule, pe parsedEvent) bool {
	if rule.Comm != "" && !strings.Contains(pe.Comm, rule.Comm) {
		return false
	}
	if rule.Path != "" && !strings.HasPrefix(pe.Path, rule.Path) {
		matched, _ := filepath.Match(rule.Path, pe.Path)
		if !matched {
			return false
		}
	}
	if rule.PathContains != "" && !strings.Contains(pe.Path, rule.PathContains) {
		return false
	}
	if rule.Mode != "" && !strings.EqualFold(rule.Mode, pe.Mode) {
		return false
	}
	return true
}

func matchRules(cfg *Config, pe parsedEvent) []Rule {
	var hits []Rule
	for _, rule := range cfg.Rules {
		if matchRule(rule, pe) {
			hits = append(hits, rule)
		}
	}
	return hits
}

func severityBlinkCode(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "\033[1;5;31m"
	case "high":
		return "\033[1;5;35m"
	case "medium":
		return "\033[1;33m"
	case "low", "info":
		return "\033[1;36m"
	default:
		return "\033[1;5;31m"
	}
}

func severityLabel(severity string) string {
	s := strings.ToUpper(severity)
	if s == "" {
		s = "ALERT"
	}
	return s
}

func main() {
	pidFilter := flag.Int("pid", 0, "Filter by process PID (0 = show all)")
	pathFilter := flag.String("path", "", "Filter by file path prefix (e.g. /etc)")
	configPath := flag.String("config", "", "Path to YAML rules config file (enables alerting)")
	alertLogPath := flag.String("alert-log", "", "Path to alert log file (overrides config)")
	flag.Parse()

	var cfg *Config
	if *configPath != "" {
		var err error
		cfg, err = loadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
		fmt.Fprintf(os.Stderr, "[watchfile] Loaded %d alert rules from %s\n", len(cfg.Rules), *configPath)
		if *alertLogPath == "" && cfg.AlertLog != "" {
			*alertLogPath = cfg.AlertLog
		}
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v\n(Hint: run 'go generate' first to compile BPF C code, or ensure clang & linux headers are installed)", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("raw_syscalls", "sys_enter", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	headerFmt := color.New(color.Bold, color.Underline)
	headerFmt.Printf("%-26s %-8s %-20s %-10s %s\n", "TIMESTAMP", "PID", "COMM", "MODE", "FILE PATH")
	fmt.Println(strings.Repeat("─", 110))

	eventCh := make(chan parsedEvent, eventQueueSize)
	alertCh := make(chan Alert, alertQueueSize)

	var s stats

	go printWorker(eventCh, &s)
	go alertWorker(alertCh, *alertLogPath, &s)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nReceived signal, exiting...")
		rd.Close()
		close(eventCh)
		close(alertCh)
		os.Exit(0)
	}()

	go func() {
		tick := time.NewTicker(statsLogPeriod)
		defer tick.Stop()
		for range tick.C {
			c := atomic.LoadUint64(&s.consumed)
			d := atomic.LoadUint64(&s.dropped)
			pd := atomic.LoadUint64(&s.printDropped)
			a := atomic.LoadUint64(&s.alerts)
			ad := atomic.LoadUint64(&s.alertDropped)
			fmt.Fprintf(os.Stderr, "[stats] consumed=%d ringbuf_dropped=%d print_dropped=%d alerts=%d alert_dropped=%d\n", c, d, pd, a, ad)
		}
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			atomic.AddUint64(&s.dropped, 1)
			continue
		}

		var e bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			atomic.AddUint64(&s.dropped, 1)
			continue
		}

		comm := strings.TrimRight(string(e.Comm[:]), "\x00")
		pathStr := strings.TrimRight(string(e.Path[:]), "\x00")

		if *pidFilter != 0 && int(e.Pid) != *pidFilter {
			continue
		}
		if *pathFilter != "" && !strings.HasPrefix(pathStr, *pathFilter) {
			continue
		}

		mode := decodeOpenFlags(e.Flags)
		pe := parsedEvent{
			Pid:    e.Pid,
			Comm:   comm,
			Path:   pathStr,
			Mode:   mode,
			ModeCl: modeColor(mode),
			CommCl: getCommColor(comm),
			Ts:     time.Now().Format("2006-01-02 15:04:05.000000"),
		}

		if cfg != nil {
			hits := matchRules(cfg, pe)
			for _, rule := range hits {
				alert := Alert{
					Rule:  rule,
					Event: pe,
					Ts:    pe.Ts,
				}
				select {
				case alertCh <- alert:
					atomic.AddUint64(&s.alerts, 1)
				default:
					atomic.AddUint64(&s.alertDropped, 1)
				}
			}
		}

		select {
		case eventCh <- pe:
			atomic.AddUint64(&s.consumed, 1)
		default:
			atomic.AddUint64(&s.printDropped, 1)
		}
	}
}

func printWorker(eventCh <-chan parsedEvent, s *stats) {
	bw := bufio.NewWriterSize(os.Stdout, printFlushBytes)
	tick := time.NewTicker(printFlushPeriod)
	defer tick.Stop()

	flush := func() {
		if bw.Buffered() > 0 {
			bw.Flush()
		}
	}

	for {
		select {
		case pe, ok := <-eventCh:
			if !ok {
				flush()
				return
			}
			formatEvent(bw, pe)
			if bw.Buffered() >= printFlushBytes-1024 {
				flush()
			}
		case <-tick.C:
			flush()
		}
	}
}

func formatEvent(w io.Writer, pe parsedEvent) {
	pe.CommCl.Fprintf(w, "%-26s ", pe.Ts)
	fmt.Fprintf(w, "%-8d ", pe.Pid)
	pe.CommCl.Fprintf(w, "%-20s ", pe.Comm)
	pe.ModeCl.Fprintf(w, "%-10s ", pe.Mode)
	fmt.Fprintln(w, pe.Path)
}

func alertWorker(alertCh <-chan Alert, logPath string, s *stats) {
	stderr := os.Stderr
	var logFile *os.File
	var logBuf *bufio.Writer
	var mu sync.Mutex

	openLogFile := func() error {
		if logPath == "" {
			return nil
		}
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("open alert log: %w", err)
		}
		logFile = f
		logBuf = bufio.NewWriterSize(f, 32*1024)
		return nil
	}

	if err := openLogFile(); err != nil {
		fmt.Fprintf(stderr, "[watchfile] Warning: %v (alerts will only be printed to terminal)\n", err)
	}

	if logFile != nil {
		defer logFile.Close()
	}

	tick := time.NewTicker(alertFlushPeriod)
	defer tick.Stop()

	flushLog := func() {
		if logBuf != nil {
			mu.Lock()
			logBuf.Flush()
			mu.Unlock()
		}
	}

	writeLogEntry := func(entry string) {
		if logBuf != nil {
			mu.Lock()
			fmt.Fprintln(logBuf, entry)
			if logBuf.Buffered() > 16*1024 {
				logBuf.Flush()
			}
			mu.Unlock()
		}
	}

	for {
		select {
		case alert, ok := <-alertCh:
			if !ok {
				flushLog()
				return
			}

			blink := severityBlinkCode(alert.Rule.Severity)
			reset := "\033[0m"
			label := severityLabel(alert.Rule.Severity)

			msg := alert.Rule.Message
			if msg == "" {
				msg = "Rule matched"
			}

			fmt.Fprintf(stderr,
				"\n%s╔══════════════════════════════════════════════════════════════════════════╗%s\n",
				blink, reset,
			)
			fmt.Fprintf(stderr,
				"%s║  [%-8s] %-65s ║%s\n",
				blink, label, msg, reset,
			)
			fmt.Fprintf(stderr,
				"%s║  Rule: %-69s ║%s\n",
				blink, alert.Rule.Name, reset,
			)
			fmt.Fprintf(stderr,
				"%s║  Time: %-69s ║%s\n",
				blink, alert.Ts, reset,
			)
			fmt.Fprintf(stderr,
				"%s║  PID:  %-8d Comm: %-28s Mode: %-6s ║%s\n",
				blink, alert.Event.Pid, alert.Event.Comm, alert.Event.Mode, reset,
			)
			fmt.Fprintf(stderr,
				"%s║  Path: %-69s ║%s\n",
				blink, alert.Event.Path, reset,
			)
			fmt.Fprintf(stderr,
				"%s╚══════════════════════════════════════════════════════════════════════════╝%s\n\n",
				blink, reset,
			)

			logEntry := fmt.Sprintf(
				"%s\t%s\t%s\tpid=%d\tcomm=%s\tmode=%s\tpath=%s\trule=%s\tmsg=%s",
				alert.Ts, label, alert.Rule.Severity,
				alert.Event.Pid, alert.Event.Comm, alert.Event.Mode,
				alert.Event.Path, alert.Rule.Name, msg,
			)
			writeLogEntry(logEntry)

		case <-tick.C:
			flushLog()
		}
	}
}
