package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	bpf "github.com/iovisor/gobpf/elf"
)

const maxCPU = 256
const maxEntryPerCPU = 128
const stackEntriesLen = 1024 // IMPORTANT: must be matching STACK_INNER_LEN in pltop.c

const maxSymbolLen = 512
const textStackEntriesLen = 256

const etype_sub_entry = 0
const etype_sub_exit = 1

var version = "dev"

type stackMeta struct {
	enabled     uint8
	outerLen    uint32
	outerOffset uint32
	outerIdx    uint32
	innerIdx    uint32

	step uint32

	reqIdx          uint32
	reqBufferLen    uint32
	reqBufferOffset uint32

	resetOuterIdxOnNewRequest uint8
	// reqURI    [2048]byte
	// reqURILen uint16
}

func (sm stackMeta) String() string {
	// return fmt.Sprintf("outerLen = %v outerOffset = %v outerIdx = %v innerIdx = %v reqIdx = %v uri = %s", sm.outerLen, sm.outerOffset, sm.outerIdx, sm.innerIdx, sm.reqIdx, sm.reqURI[:sm.reqURILen])
	return fmt.Sprintf("outerLen = %v outerOffset = %v outerIdx = %v innerIdx = %v reqIdx = %v step=%d", sm.outerLen, sm.outerOffset, sm.outerIdx, sm.innerIdx, sm.reqIdx, sm.step)
}

type stackEntry struct {
	timestamp  uint64
	file       uint64
	subroutine uint64
	line       uint32
	etype      uint8
	pid        uint64
	cpu        uint32
	reqIdx     uint32
	// depth      uint32
}

type stackEntryText struct {
	timestamp  uint64
	pid        uint64
	cpu        uint32
	reqIdx     uint32
	line       uint32
	file       [maxSymbolLen]byte
	subroutine [maxSymbolLen]byte
}

const maxURILen = 2048

type uwsgiRequest struct {
	id        uint32
	uriLen    uint16
	uri       [maxURILen]byte
	method    [16]byte
	methodLen uint16
}

type context struct {
	libperl         string
	libpsgi         string
	probes          map[string]*usdtProbe
	ppids           map[int]int // pid -> ppid
	debug           bool
	mod             *bpf.Module
	monitoredPids   []uint32
	perPidBuffer    uint32
	exitc           chan error
	dump            *os.File
	stopStartSignal chan struct{}
	stopReadySignal chan struct{}
	bpfProc         string
	requestFilter   *regexp.Regexp
	verbose         bool
}

func newContext(libperl, libpsgi string, debug bool, stackBuffer uint, bpfProc string, verbose bool) *context {
	return &context{
		debug:           debug,
		perPidBuffer:    uint32(stackBuffer),
		exitc:           make(chan error),
		libperl:         libperl,
		libpsgi:         libpsgi,
		stopStartSignal: make(chan struct{}),
		stopReadySignal: make(chan struct{}),
		bpfProc:         bpfProc,
		verbose:         verbose,
	}
}

func (ctx *context) loadUSDTProbes() error {
	libperl, err := elf.Open(ctx.libperl)
	if err != nil {
		return err
	}
	section := libperl.Section(".note.stapsdt")
	if section == nil {
		return errors.New("failed to retrieve section .note.stapsdt")
	}

	data, err := section.Data()
	if err != nil {
		return err
	}

	ctx.probes = map[string]*usdtProbe{}
	for i := 0; i < len(data); {
		namesz := binary.LittleEndian.Uint32(data[i:])
		i += 4
		descsz := binary.LittleEndian.Uint32(data[i:])
		i += 4
		typ := binary.LittleEndian.Uint32(data[i:])
		i += 4

		// TODO: support ELF_T_NHDR8
		namesz = (namesz + 3) & 0xfffffffc
		descsz = (descsz + 3) & 0xfffffffc

		var probe usdtProbe
		probe.note = string(data[i : i+int(namesz)])
		probe.typ = typ

		i += int(namesz)
		next := i + int(descsz)

		if libperl.Class == elf.ELFCLASS32 {
			return errors.New("ELFCLASS32 is not supported")
			// probe->pc = *((uint32_t *)(desc));
			// probe->base_addr = *((uint32_t *)(desc + 4));
			// probe->semaphore = *((uint32_t *)(desc + 8));
			// desc = desc + 12;
		} else {
			probe.pc = binary.LittleEndian.Uint64(data[i:])
			i += 8
			probe.baseAddr = binary.LittleEndian.Uint64(data[i:])
			i += 8
			probe.semaphore = binary.LittleEndian.Uint64(data[i:])
			i += 8
		}

		strlen := func(b []byte) (l int) {
			for i, c := range b {
				if c == 0 {
					return i
				}
			}
			return 0
		}

		probe.provider = string(data[i : i+strlen(data[i:])])
		i += strlen(data[i:]) + 1
		probe.name = string(data[i : i+strlen(data[i:])])
		i += strlen(data[i:]) + 1
		probe.argFmt = string(data[i : i+strlen(data[i:])])
		i += strlen(data[i:]) + 1

		ctx.probes[probe.name] = &probe

		i = next
	}

	return nil
}

func (ctx *context) parsePids(pidsRaw string) ([]int, error) {
	var pids []int

	// detect seperators
	var sep string
	switch {
	case strings.Contains(pidsRaw, " "):
		sep = " "
	case strings.Contains(pidsRaw, ","):
		sep = ","
	case strings.Contains(pidsRaw, ";"):
		sep = ";"
	case pidsRaw != "":
		sep = " "
	}

	if sep != "" {
		for _, p := range strings.Split(pidsRaw, sep) {
			pid, err := strconv.Atoi(p)
			if err != nil {
				return nil, err
			}
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

func (ctx *context) cleanUpOnExit() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGKILL, syscall.SIGSEGV, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGPIPE)
	go func() {
		var status int
		select {
		case <-c:
		case err := <-ctx.exitc:
			fmt.Printf("exiting due to error: %s\n", err)
			status = 1
		}

		if ctx.debug {
			fmt.Println("started cleaning up")
		}

		// stop collecting new stack entries
		for _, pid := range ctx.monitoredPids {
			if _, err := ctx.flipSemaphore("sub__entry", int(pid), -1); err != nil {
				fmt.Printf("reset semaphore %d: %s\n", pid, err)
			}
		}

		// notify other goroutines
		close(ctx.stopStartSignal)

		if ctx.debug {
			fmt.Println("stopped collecting stack frames, please wait for the program to finalize processing.")
		}

		// waiting for other goroutines to try to dump all the collected entries
		<-ctx.stopReadySignal

		if ctx.mod != nil {
			if err := ctx.mod.Close(); err != nil {
				fmt.Printf("mod.Close: %s\n", err)
			}
		}

		// TODO: remove
		if ctx.dump != nil {
			if err := ctx.dump.Close(); err != nil {
				fmt.Printf("failed to close dump file: %s\n", err)
			}
		}

		os.Stdout.Sync()

		if ctx.debug {
			fmt.Println("all set. exiting.")
		}

		os.Exit(status)
	}()

	// make sure the clean-up goroutine is started
	runtime.Gosched()
}

func (ctx *context) exit(err error) {
	if ctx.debug {
		ctx.exitc <- fmt.Errorf("%s\n%s", err, debug.Stack())
	} else {
		ctx.exitc <- err
	}

	// program should be terminated in cleanUpOnExit
	time.Sleep(3 * time.Minute)

	// close(ctx.stopReadySignal)

	fmt.Printf("failed to exit properly\n")
	os.Exit(1)
}

func (ctx *context) statUwsgiPids() error {
	rawPids, err := exec.Command("/usr/sbin/pidof", "uwsgi").CombinedOutput()
	if err != nil {
		return err
	}

	ctx.ppids = map[int]int{}
	for _, pidStr := range strings.Split(string(rawPids), " ") {
		pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
		if err != nil {
			return err
		}

		status, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "PPid") {
				continue
			}

			nodes := strings.Split(line, "\t")
			if len(nodes) != 2 {
				continue
			}

			ppid, err := strconv.Atoi(strings.TrimSpace(nodes[1]))
			if err != nil {
				return err
			}

			// pids[ppid] = append(pids[ppid], pid)
			ctx.ppids[pid] = ppid
			break
		}
	}

	return nil
}

type usdtProbe struct {
	note      string
	typ       uint32
	pc        uint64
	baseAddr  uint64
	semaphore uint64
	provider  string
	name      string
	argFmt    string
}

// TODO: check if the pid still match to the original process, it could have died already
func (ctx *context) flipSemaphore(name string, pid int, signal int) (bool, error) {
	if _, ok := ctx.probes[name]; !ok {
		return false, fmt.Errorf("unknown usdt probe %s", name)
	}

	maps, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false, err
	}

	// address                   perms offset  dev   inode   pathname
	// 7f9ef42ec000-7f9ef45d5000 r-xp 00000000 fd:00 2339175 /usr/lib64/libc-2.15.so
	var matcher = regexp.MustCompile(`([^\- ]+)\-[^\- ]+[ ]+\S+[ ]+(\S+)[ ]+\S+[ ]+\S+[ ]+(\S+)`)
	var start, offset int64
	for _, mm := range bytes.Split(maps, []byte{'\n'}) {
		matches := matcher.FindSubmatch(mm)
		if len(matches) < 4 {
			continue
		}

		if !bytes.Equal(matches[3], []byte(ctx.libperl)) {
			continue
		}

		var err error
		start, err = strconv.ParseInt(string(matches[1]), 16, 64)
		if err != nil {
			return false, err
		}
		offset, err = strconv.ParseInt(string(matches[2]), 16, 64)
		if err != nil {
			return false, err
		}

		break
	}

	// TODO: cache start, offset

	if start == 0 {
		return false, nil
		// return false, errors.New("failed to retrieve the base address of libperl.so")
	}

	// copied from bcc_syms.cc:bcc_resolve_global_addr
	// 	global addr = mod.start - mod.file_offset + address;

	semaphoreAddr := start - offset + int64(ctx.probes[name].semaphore)

	mem, err := os.OpenFile(fmt.Sprintf("/proc/%d/mem", pid), os.O_RDWR, 0600)
	if err != nil {
		return false, err
	}
	defer mem.Close()

	var buf = make([]byte, 2)
	if _, err := mem.ReadAt(buf, semaphoreAddr); err != nil {
		return false, err
	}

	semaphorev := binary.LittleEndian.Uint16(buf)
	if signal < 0 && semaphorev < 1 {
		semaphorev = 0
	} else {
		semaphorev = uint16(int(semaphorev) + signal)
	}
	binary.LittleEndian.PutUint16(buf, semaphorev)

	if ctx.debug {
		fmt.Printf("semaphorev = %+v pid = %d\n", semaphorev, pid)
	}

	if _, err := mem.WriteAt(buf, semaphoreAddr); err != nil {
		return false, err
	}

	return true, nil
}

const maxReqBufferLen uint32 = 128 // TODO: adjustable?

func (ctx *context) initBPFMod(noURI, textStack bool, targetNum int) error {
	if targetNum == 0 {
		return errors.New("initBPFMod: can't not track 0 workers")
	}

	// TODO: configurable or embed it in go binary?
	ctx.mod = bpf.NewModule(ctx.bpfProc)
	params := map[string]bpf.SectionParams{
		// "maps/requests": {MapMaxEntries: targetNum * int(maxReqBufferLen)},

		// some older kernels doesn't support bpf_probe_read_str
		"uprobe/new_uwsgi_request_with_uri": {Skipped: noURI},
	}

	// TODO: support env where number of uwsgi workers > cpu count
	if textStack {
		params["maps/text_stacks"] = bpf.SectionParams{MapMaxEntries: targetNum * int(ctx.perPidBuffer)}
	} else {
		params["maps/stacks"] = bpf.SectionParams{MapMaxEntries: targetNum * int(ctx.perPidBuffer)}
	}

	if err := ctx.mod.Load(params); err != nil {
		return fmt.Errorf("initBPFMod: %s", err)
	}
	return nil
}

// Use pidsRaw to specify which pids to trace.
// Use num to specify how many pids should be tracked.
// Use pidsRaw would disable num control.
func (ctx *context) setupWorkers(pids []int, num int, textStack bool) error {
	fpids := map[int]bool{}
	for _, pid := range pids {
		fpids[pid] = true
	}
	// fmt.Printf("fpids = %+v\n", fpids)
	for pid, ppid := range ctx.ppids {
		if ppid == 1 {
			continue
		}

		// TODO: stop if len(ctx.monitoredPids) >= num of cpu

		if (len(fpids) == 0) &&
			((num > 0 && len(ctx.monitoredPids) >= num) ||
				len(ctx.monitoredPids) > ctx.defaultTrackingCount()) {
			break
		}
		if len(fpids) > 0 && !fpids[pid] {
			continue
		}

		if ok, err := ctx.flipSemaphore("sub__entry", pid, 1); !ok || err != nil {
			if err != nil {
				return err
			}

			continue
		}

		var meta stackMeta
		meta.enabled = 1
		meta.outerLen = ctx.perPidBuffer
		meta.outerOffset = uint32(len(ctx.monitoredPids)) * ctx.perPidBuffer
		meta.outerIdx = uint32(len(ctx.monitoredPids)) * ctx.perPidBuffer
		p32 := uint32(pid)

		meta.reqBufferOffset = uint32(len(ctx.monitoredPids)) * maxReqBufferLen
		meta.reqBufferLen = maxReqBufferLen

		if textStack {
			meta.resetOuterIdxOnNewRequest = 1
		}

		ctx.monitoredPids = append(ctx.monitoredPids, p32)

		if ctx.debug {
			fmt.Printf("meta %d %s\n", pid, meta)
		}

		if err := ctx.mod.UpdateElement(ctx.mod.Map("metas"), unsafe.Pointer(&p32), unsafe.Pointer(&meta), 0); err != nil {
			return err
		}
	}

	if ctx.debug {
		fmt.Printf("ctx.monitoredPids: %v (%v)\n", ctx.monitoredPids, len(ctx.monitoredPids))
	}

	return nil
}

func (ctx *context) defaultTrackingCount() int { return len(ctx.ppids) / 3 }

func (ctx *context) attachUprobes(noURI, textStack bool) error {
	// TODO: switch to perf_event_open (check gcc)
	upEntry := ctx.mod.Uprobe("uprobe/sub_entry")
	if textStack {
		upEntry = ctx.mod.Uprobe("uprobe/sub_entry_text")
	}
	if err := bpf.AttachUprobe(upEntry, ctx.libperl, ctx.probes["sub__entry"].pc); err != nil {
		return err
	}
	upReturn := ctx.mod.Uprobe("uprobe/sub_return")
	if textStack {
		upReturn = ctx.mod.Uprobe("uprobe/sub_return_text")
	}
	if err := bpf.AttachUprobe(upReturn, ctx.libperl, ctx.probes["sub__return"].pc); err != nil {
		return err
	}

	// var canGetURI bool
	// var utsname syscall.Utsname
	// if getURI {
	// 	if err := syscall.Uname(&utsname); err != nil {
	// 		if ctx.debug {
	// 			fmt.Printf("uname failed: %s\n", err)
	// 		}
	// 	} else if utsname.Version[0] == '5' {
	// 		canGetURI = true
	// 	} else if utsname.Version[0] == '4' {
	// 		//    0 1 2 3
	// 		// >= 4 . 1 9
	// 		if utsname.Version[3] == '.' {
	// 			canGetURI = false
	// 		} else if (int(utsname.Version[2])*10 + int(utsname.Version[3])) > (int('1')*10 + '9') {
	// 			canGetURI = true
	// 		}
	// 	}
	// }

	// if ctx.debug {
	// 	fmt.Printf("retrieving uri on new request: %t %s\n", canGetURI, *(*[65]byte)(unsafe.Pointer(&utsname.Version)))
	// }

	var newUwsgiRequest *bpf.Uprobe
	if noURI {
		newUwsgiRequest = ctx.mod.Uprobe("uprobe/new_uwsgi_request_no_uri")
	} else {
		newUwsgiRequest = ctx.mod.Uprobe("uprobe/new_uwsgi_request_with_uri")
	}

	libpsgi, err := elf.Open(ctx.libpsgi)
	if err != nil {
		return err
	}
	syms, err := libpsgi.DynamicSymbols()
	if err != nil {
		return err
	}
	var uwsgiRequestSym *elf.Symbol
	for _, sym := range syms {
		if noURI && sym.Name == "uwsgi_perl_request" {
			uwsgiRequestSym = &sym
			break
		} else if !noURI && sym.Name == "psgi_call" {
			uwsgiRequestSym = &sym
			break
		}
	}
	if uwsgiRequestSym == nil {
		return errors.New("failed to retrieve psgi_call/uwsgi_perl_request symbol")
	}

	if ctx.debug {
		fmt.Printf("uwsgi_request: %#v\n", uwsgiRequestSym)
	}

	if err := bpf.AttachUprobe(newUwsgiRequest, ctx.libpsgi, uwsgiRequestSym.Value); err != nil {
		return err
	}

	return nil
}

type symTable struct {
	symbols map[uint64]map[uint64]string
	mems    map[uint64]*os.File
	err     error
}

func newSymTable() *symTable {
	return &symTable{symbols: map[uint64]map[uint64]string{}, mems: map[uint64]*os.File{}}
}

func (st *symTable) lookup(pid, addr uint64) string {
	if addr == 0 {
		return "NULL"
	}

	if st.symbols[pid] == nil {
		st.symbols[pid] = map[uint64]string{}
		f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
		if err != nil {
			st.err = err
			return ""
		}
		st.mems[pid] = f
	}

	symm := st.symbols[pid]
	if sym, ok := symm[addr]; ok {
		return sym
	}

	// TODO: support longer symbols?
	var buf = make([]byte, 1024)
	if _, err := st.mems[pid].ReadAt(buf, int64(addr)); err != nil {
		st.err = err
		return fmt.Sprintf("%x", addr)
	}

	for i, c := range buf {
		// not supporting non-printable-ascii chars.
		if c < 20 || c > 126 {
			buf[i] = '?'
		}

		if c != 0 && i < len(buf)-1 {
			continue
		}

		symm[addr] = string(buf[:i])
		break
	}

	return symm[addr]
}

func (ctx *context) top(dump string) {
	var pidCtx = [65536]struct {
		index  uint32
		reqIdx uint32
	}{}
	for i, p32 := range ctx.monitoredPids {
		pidCtx[p32].index = uint32(i) * ctx.perPidBuffer
	}

	if dump != "" {
		var err error
		ctx.dump, err = os.Create(dump)
		if err != nil {
			ctx.exit(err)
		}
	}

	var symTable = newSymTable()
	var lastRun bool
	for {
		for _, p32 := range ctx.monitoredPids {
			var meta stackMeta
			var pctx = &pidCtx[uint16(p32)]

			if err := ctx.mod.LookupElement(ctx.mod.Map("metas"), unsafe.Pointer(&p32), unsafe.Pointer(&meta)); err != nil {
				ctx.exit(err)
			}
			dumpable := pctx.reqIdx != meta.reqIdx
			if pctx.reqIdx == meta.reqIdx-1 {
				continue
			}

			// fmt.Printf("p32 = %d uint16(p32) = %d meta = %s\n", p32, uint16(p32), meta)

			pctx.reqIdx = meta.reqIdx - 1

			// TODO: handle lost data

			var allStackEntries []stackEntry
			var start, end = meta.outerIdx, uint32(0)
			var total int
			var oldIndex = pctx.index
			for i := meta.outerIdx + 1; ; {
				if i > 0 {
					i--
				} else {
					break
				}
				if i < meta.outerOffset {
					if pctx.index > meta.outerIdx {
						i = meta.outerLen + meta.outerOffset - 1
					} else {
						break
					}
				}
				end = i
				total++

				var stackEntries [stackEntriesLen]stackEntry
				if err := ctx.mod.LookupElement(ctx.mod.Map("stacks"), unsafe.Pointer(&i), unsafe.Pointer(&stackEntries)); err != nil {
					fmt.Printf("bpf_look_up_element(stacks, %d): %s\n", i, err)
					break
				}

				var shouldStop = true
				for i := stackEntriesLen - 1; i >= 0; i-- {
					se := stackEntries[i]
					if se.timestamp == 0 || se.reqIdx != meta.reqIdx-1 {
						continue
					}

					allStackEntries = append(allStackEntries, se)
					shouldStop = false
				}
				if shouldStop {
					break
				}
			}

			pctx.index = end

			var stack []stackEntry
			var depth int
			for i := len(allStackEntries) - 1; i >= 0; i-- {
				se := allStackEntries[i]

				// fmt.Printf("%d %d %s:%s:%d %d\n", se.pid, meta.reqIdx, symTable.lookup(se.pid, se.file), symTable.lookup(se.pid, se.subroutine), se.line, se.etype)

				if se.etype == 0 {
					if depth >= len(stack) {
						stack = append(stack, se)
					} else {
						stack[depth] = se
					}
					depth++
				} else if len(stack) > 0 && depth > 0 {
					depth--
				}

				if dumpable && ctx.dump != nil {
					fmt.Fprintf(ctx.dump, "%d %d %d %s:%s:%d \n", se.pid, se.reqIdx, depth, symTable.lookup(se.pid, se.file), symTable.lookup(se.pid, se.subroutine), se.line)
				}
			}

			if depth > 0 || ctx.verbose {
				for i := depth - 1; i >= 0; i-- {
					se := stack[i]
					fmt.Printf("%d %d %s:%s:%d \n", se.pid, se.reqIdx, symTable.lookup(se.pid, se.file), symTable.lookup(se.pid, se.subroutine), se.line)
				}
				fmt.Printf("p32 = %d uint16(p32) = %d meta = %s\n", p32, uint16(p32), meta)
				fmt.Printf("total_entries_read = %v/%d entries_used = %+v depth = %d start - end %d - %d pctx.index old %d new %d\n", total*stackEntriesLen, total, len(allStackEntries), depth, start, end, oldIndex, pctx.index)
				fmt.Println("----")
			}
		}

		if lastRun {
			close(ctx.stopReadySignal)
			time.Sleep(3 * time.Minute)
			fmt.Printf("failed to exit properly\n")
			os.Exit(1)
		}

		select {
		case <-ctx.stopStartSignal:
			lastRun = true
			if ctx.debug {
				fmt.Println("starting last top run")
			}
		default:
			time.Sleep(time.Second * 3)
		}
	}
}

func (ctx *context) top2(dump string) {
	if dump != "" {
		var err error
		ctx.dump, err = os.Create(dump)
		if err != nil {
			ctx.exit(err)
		}
	}

	var lastRun bool
	for {
		for _, p32 := range ctx.monitoredPids {
			var meta stackMeta
			if err := ctx.mod.LookupElement(ctx.mod.Map("metas"), unsafe.Pointer(&p32), unsafe.Pointer(&meta)); err != nil {
				ctx.exit(err)
			}
			if meta.innerIdx == 0 && meta.outerIdx == 0 {
				continue
			}

			// fmt.Printf("p32 = %d uint16(p32) = %d meta = %s\n", p32, uint16(p32), meta)

			// TODO: handle lost data

			var allStackEntries []stackEntryText
			for i := uint32(0); i <= meta.outerIdx; i++ {
				var stackEntries [textStackEntriesLen]stackEntryText
				var offset = i + meta.outerOffset
				if err := ctx.mod.LookupElement(
					ctx.mod.Map("text_stacks"),
					unsafe.Pointer(&offset),
					unsafe.Pointer(&stackEntries),
				); err != nil {
					fmt.Printf("bpf_look_up_element(stacks, %d): %s\n", i, err)
					break
				}

				if i == meta.outerIdx && meta.innerIdx <= textStackEntriesLen {
					allStackEntries = append(allStackEntries, stackEntries[:meta.innerIdx]...)
				} else {
					allStackEntries = append(allStackEntries, stackEntries[:]...)
				}
			}

			var nilEntry int
			truncate := func(bytes [maxSymbolLen]byte) []byte {
				for i, b := range bytes {
					if b == 0 {
						return bytes[:i]
					}
				}
				return bytes[:]
			}
			for i := len(allStackEntries) - 1; i >= 0; i-- {
				se := allStackEntries[i]
				if se.file != [maxSymbolLen]byte{} {
					fmt.Printf("%d %d %s:%s:%d \n", se.pid, se.reqIdx, truncate(se.file), truncate(se.subroutine), se.line)
				} else {
					nilEntry++
				}
			}
			fmt.Printf("p32 = %d uint16(p32) = %d meta = %s\n", p32, uint16(p32), meta)
			fmt.Printf("total_entries_read = %v outer/inner=%d/%d nilEntry=%d\n", len(allStackEntries), meta.outerIdx, meta.innerIdx, nilEntry)
			fmt.Println("----")
		}

		if lastRun {
			close(ctx.stopReadySignal)
			time.Sleep(3 * time.Minute)
			fmt.Printf("failed to exit properly\n")
			os.Exit(1)
		}

		select {
		case <-ctx.stopStartSignal:
			lastRun = true
			if ctx.debug {
				fmt.Println("starting last top run")
			}
		default:
			time.Sleep(time.Second * 3)
		}
	}
}

func (ctx *context) dumpAllStacks(file *os.File) {
	var pmetas = [65536]stackMeta{}
	for i, p32 := range ctx.monitoredPids {
		pmetas[p32].outerOffset = uint32(i) * ctx.perPidBuffer
		pmetas[p32].outerIdx = uint32(i) * ctx.perPidBuffer
	}

	var symTable = newSymTable()
	var lastRun bool
	for {
		for _, p32 := range ctx.monitoredPids {
			var meta stackMeta
			var pmeta = &pmetas[uint16(p32)]

			if err := ctx.mod.LookupElement(ctx.mod.Map("metas"), unsafe.Pointer(&p32), unsafe.Pointer(&meta)); err != nil {
				ctx.exit(err)
			}

			fmt.Fprintln(file, "---")
			fmt.Fprintf(file, "p32 = %d meta  = %s\n", p32, meta)
			fmt.Fprintf(file, "p32 = %d pmeta = %s\n", p32, pmeta)

			if pmeta.outerIdx == meta.outerIdx && pmeta.innerIdx == meta.innerIdx {
				continue
			}

			// TODO: handle lost data

			// var allStackEntries []stackEntry
			// var total int
			for i := pmeta.outerIdx; ; i++ {
				if (pmeta.outerIdx >= meta.outerIdx && i != pmeta.outerIdx) || (pmeta.outerIdx < meta.outerIdx && i > meta.outerIdx) {
					break
				}
				if i >= meta.outerOffset+ctx.perPidBuffer {
					i = meta.outerLen + meta.outerOffset - 1
				}

				var stackEntries [stackEntriesLen]stackEntry
				if err := ctx.mod.LookupElement(ctx.mod.Map("stacks"), unsafe.Pointer(&i), unsafe.Pointer(&stackEntries)); err != nil {
					fmt.Fprintf(file, "bpf_look_up_element(stacks, %d, %d): %s\n", p32, i, err)
					continue
				}

				var start, end uint32 = 0, stackEntriesLen
				if i == pmeta.outerIdx {
					start = pmeta.innerIdx
				}
				if i == meta.outerIdx {
					end = meta.innerIdx
				}
				fmt.Fprintf(file, "%d %d start = %d end = %d\n", p32, i, start, end)
				for j := start; j < end; j++ {
					se := stackEntries[j]
					if se.timestamp == 0 {
						continue
					}
					// continue

					fmt.Fprintf(file, "== %d %d %d.%d %s:%s:%d %d\n", se.pid, se.reqIdx, i, j, symTable.lookup(se.pid, se.file), symTable.lookup(se.pid, se.subroutine), se.line, se.etype)
				}
			}

			*pmeta = meta
		}

		if lastRun {
			file.WriteString("--- eof\n")
			file.Sync()
			file.Close()
			close(ctx.stopReadySignal)
			time.Sleep(3 * time.Minute)

			fmt.Printf("failed to exit properly\n")
			os.Exit(1)
		}

		select {
		case <-ctx.stopStartSignal:
			lastRun = true
			if ctx.debug {
				fmt.Println("starting last dumping run")
			}
		default:
			time.Sleep(time.Second * 3)
		}
	}
}

// TODO: broken
func (ctx *context) dumpAllRequests() {
	var pmetas = [65536]stackMeta{}
	for i, p32 := range ctx.monitoredPids {
		pmetas[p32].reqBufferOffset = uint32(i) * maxReqBufferLen
		// pmetas[p32].reqIdx = uint32(i) * reqBufferOffset
	}

	var lastRun bool
	for {
		for _, p32 := range ctx.monitoredPids {
			var meta stackMeta
			var pmeta = &pmetas[uint16(p32)]

			if err := ctx.mod.LookupElement(ctx.mod.Map("metas"), unsafe.Pointer(&p32), unsafe.Pointer(&meta)); err != nil {
				ctx.exit(err)
			}

			// TODO: handle lost data

			for i := pmeta.reqIdx; i < meta.reqIdx; i++ {
				var offset = i%maxReqBufferLen + meta.reqBufferOffset
				var req uwsgiRequest
				if err := ctx.mod.LookupElement(ctx.mod.Map("requests"), unsafe.Pointer(&offset), unsafe.Pointer(&req)); err != nil {
					fmt.Printf("bpf_look_up_element(requests, %d, %d): %s\n", p32, i, err)
					continue
				}

				fmt.Printf("%d %d/%d/%d %d/%d %s uri=%q\n", p32, req.id, i, offset, pmeta.reqIdx, meta.reqIdx, req.method[:req.methodLen], req.uri[:req.uriLen])
			}

			*pmeta = meta
		}

		if lastRun {
			close(ctx.stopReadySignal)
			time.Sleep(3 * time.Minute)

			fmt.Printf("failed to exit properly\n")
			os.Exit(1)
		}

		select {
		case <-ctx.stopStartSignal:
			lastRun = true
			if ctx.debug {
				fmt.Println("starting last dumping run")
			}
		default:
			time.Sleep(time.Second * 3)
		}
	}
}

func (ctx *context) genFlameGraph(path string, ratio int) {
	var pmetas = [65536]stackMeta{}
	for i, p32 := range ctx.monitoredPids {
		pmetas[p32].outerOffset = uint32(i) * ctx.perPidBuffer
		pmetas[p32].outerIdx = uint32(i) * ctx.perPidBuffer
		// pmetas[p32].reqIdx = uint32(i) * maxReqBufferLen
	}

	fgf, err := os.Create(path)
	if err != nil {
		ctx.exit(err)
	}

	rand.Seed(time.Now().UnixNano())

	var lastRun bool
	var symTable = newSymTable()
	var stackInfo = map[string]int{}
	var stats struct {
		stacks        int
		framesFetched int
		framesLogged  int
		reqFetched    int
		reqSkipped    int
	}
	var stackPerPid = make([][]stackEntry, len(ctx.monitoredPids))
	var matchedReqId = make([]map[uint32]bool, len(ctx.monitoredPids))
	for {
		for pindex, p32 := range ctx.monitoredPids {
			var meta stackMeta
			var pmeta = &pmetas[uint16(p32)]

			if err := ctx.mod.LookupElement(ctx.mod.Map("metas"), unsafe.Pointer(&p32), unsafe.Pointer(&meta)); err != nil {
				ctx.exit(err)
			}

			// fmt.Fprintln(file, "---")
			// fmt.Fprintf(file, "p32 = %d meta  = %s\n", p32, meta)
			// fmt.Fprintf(file, "p32 = %d pmeta = %s\n", p32, pmeta)

			if pmeta.outerIdx == meta.outerIdx && pmeta.innerIdx == meta.innerIdx || meta.innerIdx == 0 {
				continue
			}

			if ctx.requestFilter != nil {
				if matchedReqId[pindex] == nil {
					matchedReqId[pindex] = map[uint32]bool{}
				}

				for i := pmeta.reqIdx; i < meta.reqIdx; i++ {
					stats.reqFetched++

					var offset = i%maxReqBufferLen + meta.reqBufferOffset
					var req uwsgiRequest
					if err := ctx.mod.LookupElement(ctx.mod.Map("requests"), unsafe.Pointer(&offset), unsafe.Pointer(&req)); err != nil {
						fmt.Printf("bpf_look_up_element(requests, %d, %d): %s\n", p32, i, err)
						continue
					}

					if ctx.requestFilter.MatchString(fmt.Sprintf("%s %s", req.method[:req.methodLen], req.uri[:req.uriLen])) {
						matchedReqId[pindex][req.id] = true

						if ctx.verbose {
							fmt.Printf("matched request: %s %s\n", req.method[:req.methodLen], req.uri[:req.uriLen])
						}
					} else {
						stats.reqSkipped++
					}
				}
			}

			// TODO: handle lost data

			for i := pmeta.outerIdx; ; i++ {
				if (pmeta.outerIdx >= meta.outerIdx && i != pmeta.outerIdx) || (pmeta.outerIdx < meta.outerIdx && i > meta.outerIdx) {
					break
				}
				if i >= meta.outerOffset+ctx.perPidBuffer {
					i = meta.outerLen + meta.outerOffset - 1
				}

				// TODO: doesn't sacle very well on app boxes because there are too many stack frames collected

				var stackEntries [stackEntriesLen]stackEntry
				if err := ctx.mod.LookupElement(ctx.mod.Map("stacks"), unsafe.Pointer(&i), unsafe.Pointer(&stackEntries)); err != nil {
					ctx.exit(err)
				}
				stats.stacks++

				var start, end uint32 = 0, stackEntriesLen
				if i == pmeta.outerIdx {
					start = pmeta.innerIdx
				}
				if i == meta.outerIdx {
					end = meta.innerIdx
				}

				for j := start; j < end; j++ {
					se := stackEntries[j]
					if se.timestamp == 0 || se.reqIdx == 0 {
						continue
					}

					stats.framesFetched++

					// skip by uri-filter
					if matchedReqId[pindex] != nil && !matchedReqId[pindex][se.reqIdx] {
						continue
					}

					stack := stackPerPid[pindex]

					// trying to reset stacks on every new request
					if j > 0 && stackEntries[j].reqIdx != se.reqIdx {
						stack = stack[:0]
					}
					if len(stack) > 0 {
						for _, pse := range stack {
							if pse.reqIdx != se.reqIdx {
								stack = stack[:0]
								break
							}
						}
					}

					if se.etype == etype_sub_entry {
						stack = append(stack, se)
					} else if se.etype == etype_sub_exit {
						if len(stack) == 0 {
							fmt.Printf("negative stack depth detected\n")
						} else {
							stack = stack[:len(stack)-1]
						}
					}
					stackPerPid[pindex] = stack

					if ratio < rand.Intn(100) {
						continue
					}
					stats.framesLogged++

					// The input is stack frames and sample counts formatted as single lines.
					// Each frame in the stack is semicolon separated, with a space and count
					// at the end of the line.  These can be generated for Linux perf script
					// output using stackcollapse-perf.pl, for DTrace using stackcollapse.pl,
					// and for other tools
					// using the other stackcollapse programs.  Example input:
					//
					//  swapper;start_kernel;rest_init;cpu_idle;default_idle;native_safe_halt 1

					var frame string
					for _, se := range stack {
						frame += fmt.Sprintf("%s::%s::%d;", symTable.lookup(se.pid, se.file), symTable.lookup(se.pid, se.subroutine), se.line)
						stackInfo[frame] += 1
					}
				}
			}

			*pmeta = meta
		}

		if lastRun {
			// stats.frames = len(stackInfo)

			var stacks []string
			for frame, count := range stackInfo {
				// trim trailing semicolon
				if len(frame) > 2 && frame[len(frame)-1] == ';' {
					frame = frame[:len(frame)-2]
				}
				stacks = append(stacks, fmt.Sprintf("%s %d", frame, count))
			}

			sort.Strings(stacks)
			for _, frame := range stacks {
				_, err := fgf.WriteString(ctx.fmtFilename(frame) + "\n")
				if err != nil {
					fmt.Printf("failed to generate flamegraph: %s\b", err)
					break
				}
			}

			// fgf.WriteString("--- eof\n")
			fgf.Sync()
			fgf.Close()
			close(ctx.stopReadySignal)

			fmt.Printf("stat: frames_count %d frames_{fetched/logged} %d/%d stacks_syscall: %d request_{skipped/fetched}: %d/%d\n", len(stackInfo), stats.framesFetched, stats.framesLogged, stats.stacks, stats.reqSkipped, stats.reqFetched)

			time.Sleep(3 * time.Minute)

			fmt.Printf("failed to exit properly\n")
			os.Exit(1)
		}

		select {
		case <-ctx.stopStartSignal:
			lastRun = true
			if ctx.debug {
				fmt.Println("starting last dumping run")
			}
		default:
			time.Sleep(time.Second * 3)
		}
	}
}

func (ctx *context) fmtFilename(fn string) string { return fn }

func main() {
	var (
		pids        = flag.String("pids", "", "a list of pids (comma/space separated), it overrides -num")
		num         = flag.Int("num", 1, "number of uwsgi workers to be monitored")
		debug       = flag.Bool("debug", false, "print out debug info")
		stackBuffer = flag.Uint("buffer", stackEntriesLen, "stack buffer size")
		help        = flag.Bool("help", false, "print help messages")

		libperl = flag.String("perl", "", "path to libperl.so")
		libpsgi = flag.String("psgi", "", "path to uwsgi psgi shared library")

		noURI = flag.Bool("no-uri", false, "do not retrieve uri for every new uwsgi request (use it with kernel version lower than 4.19)")

		output = flag.String("output", "", "dump all stack entries to file")

		ratio = flag.Int("ratio", 10, "stack frame stat ratio 0 - 100")

		bpfProc = flag.String("bpfproc", "/opt/plperf.o", "path to the plperf.o bpf object file")

		fversion = flag.Bool("version", false, "print out version")

		verbose = flag.Bool("verbose", false, "print out version")

		requestFilter = flag.String("uri-filter", "", "only tracks matched request uri (go regular expression syntax). an exmpale uri: 'GET /ordres?id=1'")

		// timeout = flag.Int("timeout", 0, "exit uwperf after specified seconds")
	)
	flag.BoolVar(help, "h", false, "print help messages")
	flag.Parse()

	if *fversion {
		fmt.Println(version)
		return
	}
	if *help || flag.Arg(0) == "" {
		fmt.Println("plperf [options] <command>")
		fmt.Println("")
		fmt.Println("supported commands:")
		fmt.Println("  top: prints out a snapshot of the stacks of the traced uwsgi+perl workers")
		fmt.Println("  flame: generates a flamegraph input file of the traced uwsgi+perl workers")
		// fmt.Println("    reset: force reset/cleanup uprobe events and semaphore values")

		fmt.Println("")
		flag.PrintDefaults()

		fmt.Println("")
		fmt.Println("Examples:")
		fmt.Println("	sudo plperf -debug top")
		fmt.Println("	sudo plperf -debug -num 5 top")
		fmt.Println("")
		fmt.Println("	sudo timeout 5 plperf -debug -output flame.txt -num 1 flame")
		fmt.Println("	sudo timeout 5 plperf -debug -output flame.txt -uri-filter 'GET /orders.*' -num 1 flame")
		return
	}

	ctx := newContext(*libperl, *libpsgi, *debug, *stackBuffer, *bpfProc, *verbose)
	if *requestFilter != "" {
		exp, err := regexp.Compile(*requestFilter)
		if err != nil {
			fmt.Printf("req-filter not a proper regexp: %s\n", err)
			os.Exit(1)
		}
		ctx.requestFilter = exp
	}

	var parsedPids []int
	if *pids != "" {
		var err error
		parsedPids, err = ctx.parsePids(*pids)
		if err != nil {
			fmt.Printf("failed to parse pids: %s\n", err)
			os.Exit(1)
		}
	}

	ctx.cleanUpOnExit()
	defer func() {
		if r := recover(); r != nil {
			close(ctx.stopReadySignal)
			if err, ok := r.(error); ok {
				ctx.exit(err)
			} else {
				ctx.exit(fmt.Errorf("%+v", err))
			}
		}
	}()

	// TODO: detects and warns if not using perl dtrace
	// TODO: add a clean up command

	if err := ctx.loadUSDTProbes(); err != nil {
		close(ctx.stopReadySignal)
		ctx.exit(err)
	}
	if err := ctx.statUwsgiPids(); err != nil {
		close(ctx.stopReadySignal)
		ctx.exit(err)
	}

	var targetNum = ctx.defaultTrackingCount()
	if len(parsedPids) > 0 {
		targetNum = len(parsedPids)
	} else if *num > 0 {
		targetNum = *num
	}

	var textStack = flag.Arg(0) == "top2"
	if err := ctx.initBPFMod(*noURI, textStack, targetNum); err != nil {
		close(ctx.stopReadySignal)
		ctx.exit(err)
	}

	if err := ctx.setupWorkers(parsedPids, *num, textStack); err != nil {
		close(ctx.stopReadySignal)
		ctx.exit(err)
	}
	if err := ctx.attachUprobes(*noURI, textStack); err != nil {
		close(ctx.stopReadySignal)
		ctx.exit(err)
	}

	switch flag.Arg(0) {
	case "top":
		ctx.top(*output)
	case "top2":
		ctx.top2(*output)
	case "requests":
		ctx.dumpAllRequests()
	case "flame":
		if *output == "" {
			*output = "flame.txt"
		}
		ctx.genFlameGraph(*output, *ratio)
	case "dump":
		file, err := os.Create(*output)
		if err != nil {
			ctx.exit(err)
		}
		ctx.dumpAllStacks(file)
	// case "reset":
	// 	ue, err := os.OpenFile("/sys/kernel/debug/tracing/uprobe_events", os.O_WRONLY, 0744)
	// 	if err != nil {
	// 		fmt.Printf("open uprobe_events: %s", err)
	// 	} else {
	// 		ue.WriteString("")
	// 		ue.Close()
	// 	}
	default:
		ctx.exit(fmt.Errorf("unknown upperf command: %s", flag.Arg(0)))
	}
}
