package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/fatih/color"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target bpf -type event bpf openat_trace.c

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

	go func() {
		<-sigCh
		fmt.Println("\n\nReceived signal, exiting...")
		rd.Close()
		os.Exit(0)
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return
			}
			log.Printf("Reading from ringbuf: %v", err)
			continue
		}

		var e bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			log.Printf("Parsing event: %v", err)
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
		ts := time.Now().Format("2006-01-02 15:04:05.000000")

		commClr := getCommColor(comm)
		modeClr := modeColor(mode)

		commClr.Printf("%-26s ", ts)
		fmt.Printf("%-8d ", e.Pid)
		commClr.Printf("%-20s ", comm)
		modeClr.Printf("%-10s ", mode)
		fmt.Println(pathStr)
	}
}
