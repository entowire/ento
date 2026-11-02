//go:build windows

// ento-tray shows the person at a Windows computer whether their ento session is open, tells
// them when it ends, and signs them in and out without an administrator (0.35). It holds nothing:
// it asks the agent's service over the person's channel (internal/agent/session.go), which runs
// the sign-in with the device's key, and opens the sign-in page in the person's own browser.
// Started at every sign-in to Windows (HKLM Run, written by `ento agent install`).
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"entowire.com/ento/internal/agent"
)

var version = "dev"

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	pRegisterClassExW       = user32.NewProc("RegisterClassExW")
	pCreateWindowExW        = user32.NewProc("CreateWindowExW")
	pDefWindowProcW         = user32.NewProc("DefWindowProcW")
	pGetMessageW            = user32.NewProc("GetMessageW")
	pTranslateMessage       = user32.NewProc("TranslateMessage")
	pDispatchMessageW       = user32.NewProc("DispatchMessageW")
	pPostMessageW           = user32.NewProc("PostMessageW")
	pPostQuitMessage        = user32.NewProc("PostQuitMessage")
	pCreatePopupMenu        = user32.NewProc("CreatePopupMenu")
	pAppendMenuW            = user32.NewProc("AppendMenuW")
	pTrackPopupMenu         = user32.NewProc("TrackPopupMenu")
	pDestroyMenu            = user32.NewProc("DestroyMenu")
	pSetForegroundWindow    = user32.NewProc("SetForegroundWindow")
	pGetCursorPos           = user32.NewProc("GetCursorPos")
	pRegisterWindowMessageW = user32.NewProc("RegisterWindowMessageW")
	pCreateIconIndirect     = user32.NewProc("CreateIconIndirect")
	pDestroyIcon            = user32.NewProc("DestroyIcon")
	pGetSystemMetrics       = user32.NewProc("GetSystemMetrics")
	pMessageBoxW            = user32.NewProc("MessageBoxW")
	pShellNotifyIconW       = shell32.NewProc("Shell_NotifyIconW")
	pCreateDIBSection       = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap           = gdi32.NewProc("CreateBitmap")
	pDeleteObject           = gdi32.NewProc("DeleteObject")
	pGetModuleHandleW       = kernel32.NewProc("GetModuleHandleW")
	pSetProcessDPIAwareness = user32.NewProc("SetProcessDPIAware")
)

const (
	wmNull        = 0x0000
	wmDestroy     = 0x0002
	wmClose       = 0x0010
	wmCommand     = 0x0111
	wmTimer       = 0x0113
	wmLButtonUp   = 0x0202
	wmRButtonUp   = 0x0205
	wmApp         = 0x8000
	wmTray        = wmApp + 1 // the icon's events
	wmRefresh     = wmApp + 2 // the agent's answer changed
	wmBalloon     = wmApp + 3 // a notification to show
	ninBalloonClk = 0x0405    // NIN_BALLOONUSERCLICK

	nimAdd    = 0
	nimModify = 1
	nimDelete = 2
	nifMsg    = 0x01
	nifIcon   = 0x02
	nifTip    = 0x04
	nifInfo   = 0x10
	niifInfo  = 0x01
	niifWarn  = 0x02

	mfString    = 0x0000
	mfGrayed    = 0x0001
	mfSeparator = 0x0800
	tpmRetCmd   = 0x0100
	tpmRightBtn = 0x0002
	tpmNoNotify = 0x0080

	smCxSmIcon = 49
	mbIconInfo = 0x40

	cmdSignIn  = 1
	cmdSignOut = 2
	cmdStatus  = 3
	cmdExit    = 4
)

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

type point struct{ x, y int32 }

type msg struct {
	hwnd    windows.HWND
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
	private uint32
}

type notifyIconData struct {
	size        uint32
	hwnd        windows.HWND
	id          uint32
	flags       uint32
	callbackMsg uint32
	icon        windows.Handle
	tip         [128]uint16
	state       uint32
	stateMask   uint32
	info        [256]uint16
	version     uint32
	infoTitle   [64]uint16
	infoFlags   uint32
	guidItem    windows.GUID
	balloonIcon windows.Handle
}

type iconInfo struct {
	isIcon   int32
	xHotspot uint32
	yHotspot uint32
	mask     windows.Handle
	color    windows.Handle
}

type bitmapInfoHeader struct {
	size          uint32
	width         int32
	height        int32
	planes        uint16
	bitCount      uint16
	compression   uint32
	sizeImage     uint32
	xPelsPerMeter int32
	yPelsPerMeter int32
	clrUsed       uint32
	clrImportant  uint32
}

// view is what the agent last said, and what the person was last told.
type view struct {
	reachable bool // the agent answered on the person's channel
	err       string
	st        agent.SessionReply
	signingIn bool
}

type balloon struct {
	title, text string
	warn        bool
	signIn      bool // a click on it starts a sign-in
}

type tray struct {
	hwnd    windows.HWND
	icons   map[string]windows.Handle
	shown   string // the icon shown
	created uint32 // TaskbarCreated: Explorer restarted, the icon must be added again
	mu      sync.Mutex
	v       view
	pending []balloon
	clickIn bool // the last notification signs in when clicked
	told    bool // the person was told their session ended (until it opens again); under mu
	wake    chan struct{}
}

func main() {
	runtime.LockOSThread()
	name, _ := windows.UTF16PtrFromString(`Local\ento-tray`)
	if _, err := windows.CreateMutex(nil, false, name); errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return // one per Windows session
	}
	pSetProcessDPIAwareness.Call()
	t := &tray{icons: map[string]windows.Handle{}, wake: make(chan struct{}, 1)}
	if err := t.run(); err != nil {
		text, _ := windows.UTF16PtrFromString("ento: " + err.Error())
		title, _ := windows.UTF16PtrFromString("ento")
		pMessageBoxW.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), mbIconInfo)
		os.Exit(1)
	}
}

func (t *tray) run() error {
	inst, _, _ := pGetModuleHandleW.Call(0)
	cls, _ := windows.UTF16PtrFromString("ento-tray")
	wc := wndClassEx{wndProc: windows.NewCallback(t.wndProc), instance: windows.Handle(inst), className: cls}
	wc.size = uint32(unsafe.Sizeof(wc))
	if r, _, err := pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); r == 0 {
		return fmt.Errorf("register window class: %v", err)
	}
	// A message-only window would not receive TaskbarCreated (a broadcast): a hidden one does.
	h, _, err := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(cls)), uintptr(unsafe.Pointer(cls)), 0, 0, 0, 0, 0, 0, 0, inst, 0)
	if h == 0 {
		return fmt.Errorf("create window: %v", err)
	}
	t.hwnd = windows.HWND(h)
	tc, _ := windows.UTF16PtrFromString("TaskbarCreated")
	r, _, _ := pRegisterWindowMessageW.Call(uintptr(unsafe.Pointer(tc)))
	t.created = uint32(r)
	for _, s := range []string{"open", "closed", "away"} {
		t.icons[s] = makeIcon(s)
	}
	t.shown = "away"
	t.notify(nimAdd, "ento: asking the agent...")
	defer t.notify(nimDelete, "")
	go t.poll()

	var m msg
	for {
		r, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(r) <= 0 {
			return nil
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

// poll asks the agent every 15 seconds, and at once when woken (after a sign-in or sign-out).
func (t *tray) poll() {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		st, err := agent.SessionStatus(ctx)
		cancel()
		t.mu.Lock()
		t.v.reachable, t.v.st, t.v.err = err == nil, st, ""
		if err != nil && !errors.Is(err, agent.ErrNoSessionChannel) {
			t.v.err = err.Error()
		}
		t.mu.Unlock()
		pPostMessageW.Call(uintptr(t.hwnd), wmRefresh, 0, 0)
		select {
		case <-t.wake:
		case <-time.After(15 * time.Second):
		}
	}
}

func (t *tray) refreshSoon() {
	select {
	case t.wake <- struct{}{}:
	default:
	}
}

func (t *tray) say(b balloon) {
	t.mu.Lock()
	t.pending = append(t.pending, b)
	t.mu.Unlock()
	pPostMessageW.Call(uintptr(t.hwnd), wmBalloon, 0, 0)
}

func (t *tray) wndProc(hwnd, message, wParam, lParam uintptr) uintptr {
	switch uint32(message) {
	case wmTray:
		switch uint32(lParam) {
		case wmRButtonUp, wmLButtonUp:
			t.menu()
		case ninBalloonClk:
			if t.clickIn {
				t.signIn()
			}
		}
		return 0
	case wmRefresh:
		t.refresh()
		return 0
	case wmBalloon:
		t.mu.Lock()
		bs := t.pending
		t.pending = nil
		t.mu.Unlock()
		for _, b := range bs {
			t.balloon(b)
		}
		return 0
	case wmClose:
		pPostQuitMessage.Call(0)
		return 0
	case wmDestroy:
		pPostQuitMessage.Call(0)
		return 0
	}
	if t.created != 0 && uint32(message) == t.created {
		t.notify(nimAdd, t.tip())
		return 0
	}
	r, _, _ := pDefWindowProcW.Call(hwnd, message, wParam, lParam)
	return r
}

// refresh shows the agent's latest answer, and tells the person once when their session ended.
func (t *tray) refresh() {
	t.mu.Lock()
	v := t.v
	switch {
	case !v.reachable:
		t.shown = "away"
	case v.st.SessionActive:
		t.shown = "open"
		t.told = false
	default:
		t.shown = "closed"
	}
	// A device nobody signed in to (a shared or new one) is not nagged; one whose person's
	// session ended is, once: at each start of Windows (a restart closes it) and when it ends.
	tell := v.reachable && v.st.User != "" && !v.st.SessionActive && !v.signingIn && !t.told
	if tell {
		t.told = true
	}
	t.mu.Unlock()
	t.notify(nimModify, t.tip())
	if tell {
		t.balloon(balloon{title: "ento: sign in again", warn: true, signIn: true,
			text: "Your ento session has ended, so your organisation's services are out of reach. Click here to sign in."})
	}
}

func (t *tray) tip() string {
	t.mu.Lock()
	v := t.v
	t.mu.Unlock()
	switch {
	case v.signingIn:
		return "ento: signing in..."
	case !v.reachable:
		return "ento: the agent is not running"
	case v.st.SessionActive:
		return "ento: signed in as " + agent.Printable(v.st.User)
	case v.st.User != "":
		return "ento: session ended, sign in again"
	}
	return "ento: nobody signed in"
}

func (t *tray) menu() {
	t.mu.Lock()
	v := t.v
	t.mu.Unlock()
	m, _, _ := pCreatePopupMenu.Call()
	if m == 0 {
		return
	}
	defer pDestroyMenu.Call(m)
	add := func(flags uint32, id int, text string) {
		p, _ := windows.UTF16PtrFromString(text)
		pAppendMenuW.Call(m, uintptr(flags), uintptr(id), uintptr(unsafe.Pointer(p)))
	}
	add(mfString|mfGrayed, 0, t.tip())
	add(mfSeparator, 0, "")
	inFlags, outFlags := uint32(mfString), uint32(mfString)
	if !v.reachable || v.signingIn {
		inFlags |= mfGrayed
	}
	if !v.reachable || !v.st.SessionActive {
		outFlags |= mfGrayed
	}
	add(inFlags, cmdSignIn, "Sign in...")
	add(outFlags, cmdSignOut, "Sign out")
	add(mfString, cmdStatus, "Status")
	add(mfSeparator, 0, "")
	add(mfString, cmdExit, "Hide until next sign-in to Windows")
	var p point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&p)))
	pSetForegroundWindow.Call(uintptr(t.hwnd)) // or the menu does not close when clicking elsewhere
	cmd, _, _ := pTrackPopupMenu.Call(m, tpmRetCmd|tpmRightBtn|tpmNoNotify, uintptr(p.x), uintptr(p.y), 0, uintptr(t.hwnd), 0)
	pPostMessageW.Call(uintptr(t.hwnd), wmNull, 0, 0)
	switch cmd {
	case cmdSignIn:
		t.signIn()
	case cmdSignOut:
		t.signOut()
	case cmdStatus:
		t.status()
	case cmdExit:
		pPostQuitMessage.Call(0)
	}
}

// signIn asks the agent to start a sign-in and opens its page in the person's browser.
func (t *tray) signIn() {
	t.mu.Lock()
	if t.v.signingIn {
		t.mu.Unlock()
		return
	}
	t.v.signingIn = true
	t.mu.Unlock()
	t.clickIn = false
	t.notify(nimModify, t.tip())
	go func() {
		defer func() {
			t.mu.Lock()
			t.v.signingIn = false
			t.mu.Unlock()
			t.refreshSoon()
		}()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		err := agent.SessionDo(ctx, "login", func(r agent.SessionReply) error {
			switch r.Event {
			case "link":
				if !agent.SafeLink(r.Link) {
					return errors.New("the control node sent a sign-in link that is not a plain https link; it was not opened")
				}
				if agent.OpenBrowser(r.Link) {
					t.say(balloon{title: "ento: sign in in your browser", text: "Confirm the code " + agent.Printable(r.Code) + " and sign in with your password and security key or passkey."})
				} else {
					t.say(balloon{title: "ento: sign in", text: "Open " + agent.Printable(r.Link) + " in a browser and confirm the code " + agent.Printable(r.Code) + "."})
				}
			case "done":
				text := "Signed in as " + agent.Printable(r.User) + "."
				if !r.Approved {
					text += " Your groups do not approve devices: ask an administrator."
				}
				t.say(balloon{title: "ento", text: text})
			}
			return nil
		})
		if err != nil {
			t.say(balloon{title: "ento: not signed in", text: err.Error(), warn: true, signIn: true})
		}
	}()
}

func (t *tray) signOut() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		delivered, err := agent.LogoutViaAgent(ctx)
		switch {
		case err != nil:
			t.say(balloon{title: "ento: not signed out", text: err.Error(), warn: true})
		case delivered:
			t.say(balloon{title: "ento", text: "Signed out: this computer keeps only what it may reach without you."})
		default:
			t.say(balloon{title: "ento", text: "The network could not be reached: the agent signs you out as soon as it can."})
		}
		t.mu.Lock()
		t.told = true // signing out is not the session ending on its own
		t.mu.Unlock()
		t.refreshSoon()
	}()
}

func (t *tray) status() {
	t.mu.Lock()
	v := t.v
	t.mu.Unlock()
	text := t.tip()
	switch {
	case !v.reachable && v.err != "":
		text += "\n\n" + v.err
	case !v.reachable:
		text += "\n\nThe ento service is stopped or older than 0.35. An administrator can check it with: ento agent status"
	default:
		if v.st.UserName != "" && v.st.UserName != v.st.User {
			text += " (" + agent.Printable(v.st.UserName) + ")"
		}
		text += "\n\nAgent: ento " + agent.Printable(v.st.Version) + "\nTray: ento " + version
		if v.st.User != "" && !v.st.SessionActive {
			text += "\n\nYour session ends after 8 hours without use, when you sign out and when Windows restarts. Sign in again from this icon."
		}
	}
	p, _ := windows.UTF16PtrFromString(text)
	title, _ := windows.UTF16PtrFromString("ento")
	pMessageBoxW.Call(uintptr(t.hwnd), uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(title)), mbIconInfo)
}

func (t *tray) notify(op uint32, tip string) {
	d := notifyIconData{hwnd: t.hwnd, id: 1, callbackMsg: wmTray, icon: t.icons[t.shown]}
	d.size = uint32(unsafe.Sizeof(d))
	if op != nimDelete {
		d.flags = nifMsg | nifIcon | nifTip
		copyUTF16(d.tip[:], tip)
	}
	pShellNotifyIconW.Call(uintptr(op), uintptr(unsafe.Pointer(&d)))
}

func (t *tray) balloon(b balloon) {
	t.clickIn = b.signIn
	d := notifyIconData{hwnd: t.hwnd, id: 1, flags: nifInfo, infoFlags: niifInfo}
	d.size = uint32(unsafe.Sizeof(d))
	if b.warn {
		d.infoFlags = niifWarn
	}
	copyUTF16(d.infoTitle[:], b.title)
	copyUTF16(d.info[:], b.text)
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&d)))
}

// copyUTF16 writes s into a fixed, NUL-terminated buffer, cut to fit.
func copyUTF16(dst []uint16, s string) {
	u := syscall.StringToUTF16(s)
	if len(u) > len(dst) {
		u = append(u[:len(dst)-1], 0)
	}
	copy(dst, u)
}

// makeIcon draws the tray icon for a state: a rounded square, blue with a lit cell while the session
// is open, grey while it is closed, amber with a dark cell while the agent does not answer.
func makeIcon(state string) windows.Handle {
	n, _, _ := pGetSystemMetrics.Call(smCxSmIcon)
	size := int(n)
	if size < 16 {
		size = 16
	}
	fill, cell := [3]byte{0x36, 0x56, 0xff}, [3]byte{0xff, 0xff, 0xff}
	switch state {
	case "closed":
		fill = [3]byte{0x7c, 0x81, 0x8a}
	case "away":
		fill, cell = [3]byte{0xd9, 0x77, 0x06}, [3]byte{0x2a, 0x1a, 0x00}
	}
	bi := bitmapInfoHeader{width: int32(size), height: -int32(size), planes: 1, bitCount: 32}
	bi.size = uint32(unsafe.Sizeof(bi))
	var bits unsafe.Pointer
	color, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if color == 0 {
		return 0
	}
	defer pDeleteObject.Call(color)
	px := unsafe.Slice((*byte)(bits), size*size*4)
	margin, radius := size/16, size/5
	c0, c1 := size*9/16, size*13/16 // the cell, lower right
	for y := range size {
		for x := range size {
			i := (y*size + x) * 4
			if !inRounded(x, y, margin, size-1-margin, radius) {
				continue
			}
			rgb := fill
			if x >= c0 && x < c1 && y >= c0 && y < c1 {
				rgb = cell
			}
			px[i], px[i+1], px[i+2], px[i+3] = rgb[2], rgb[1], rgb[0], 0xff
		}
	}
	// The mask is unused (the alpha channel decides) but required: rows of whole 16-bit words.
	maskBits := make([]byte, (size+15)/16*2*size)
	mask, _, _ := pCreateBitmap.Call(uintptr(size), uintptr(size), 1, 1, uintptr(unsafe.Pointer(&maskBits[0])))
	if mask == 0 {
		return 0
	}
	defer pDeleteObject.Call(mask)
	ii := iconInfo{isIcon: 1, mask: windows.Handle(mask), color: windows.Handle(color)}
	h, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	return windows.Handle(h)
}

func inRounded(x, y, lo, hi, r int) bool {
	if x < lo || x > hi || y < lo || y > hi {
		return false
	}
	cx, cy := x, y
	switch {
	case x < lo+r:
		cx = lo + r
	case x > hi-r:
		cx = hi - r
	}
	switch {
	case y < lo+r:
		cy = lo + r
	case y > hi-r:
		cy = hi - r
	}
	dx, dy := x-cx, y-cy
	return dx*dx+dy*dy <= r*r
}
