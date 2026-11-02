package agent

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func sysBootTime() string {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return ""
	}
	return fmt.Sprintf("boot-%d-%d", tv.Sec, tv.Usec)
}
