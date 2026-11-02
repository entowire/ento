package agent

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemTimeOfDay is SYSTEM_TIMEOFDAY_INFORMATION: BootTime is when the system booted (FILETIME
// units, 100 ns), moved along whenever the clock is set (time sync); BootTimeBias is the sum of
// those moves, so BootTime - BootTimeBias stays the same for as long as the system runs.
type systemTimeOfDay struct {
	BootTime      int64
	CurrentTime   int64
	TimeZoneBias  int64
	TimeZoneID    uint32
	Reserved      uint32
	BootTimeBias  uint64
	SleepTimeBias uint64
}

// sysBootTime identifies the current boot (0.32.3; before, Windows reported none, so a person's
// session outlived a restart): the boot time without the clock's later corrections, to the second.
// A shutdown with Windows' fast startup resumes the kernel instead of booting it, and keeps the boot
// time: only a restart (or a full shutdown) is a new boot.
func sysBootTime() string {
	var t systemTimeOfDay
	var n uint32
	if err := windows.NtQuerySystemInformation(windows.SystemTimeOfDayInformation, unsafe.Pointer(&t), uint32(unsafe.Sizeof(t)), &n); err != nil || t.BootTime == 0 {
		return ""
	}
	return fmt.Sprintf("boot-%d", (t.BootTime-int64(t.BootTimeBias))/10_000_000)
}
