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
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/color"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target bpf -type event bpf openat_trace.c

const (
	eventQueueSize   = 16384
	printFlushBytes  = 64 * 1024
	printFlushPeriod = 50 * time.Millisecond
	statsLogPeriod   = 30 * time.Second
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
	consumed   uint64
	dropped    uint64
	printDropped uint64
}

func main() {
	pidFilter := flag.Int("pid", 0, "Filter by process PID (0 = show all)")
	pathFilter := flag.String("path", "", "Filter by file path prefix (e.g. /etc)")
	flag.Parse()

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

	var s stats

	go printWorker(eventCh, &s)

	go func() {
		<-sigCh
		fmt.Fprintln(os.Stderr, "\nReceived signal, exiting...")
		rd.Close()
		close(eventCh)
		os.Exit(0)
	}()

	go func() {
		tick := time.NewTicker(statsLogPeriod)
		defer tick.Stop()
		for range tick.C {
			c := atomic.LoadUint64(&s.consumed)
			d := atomic.LoadUint64(&s.dropped)
			pd := atomic.LoadUint64(&s.printDropped)
			fmt.Fprintf(os.Stderr, "[stats] consumed=%d ringbuf_dropped=%d print_dropped=%d\n", c, d, pd)
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

	// print a batch without trying to write one line per syscall
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
