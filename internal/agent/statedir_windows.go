package agent

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// protectStateDir gives a state directory a protected DACL (SYSTEM and Administrators only): it
// holds the device's private key, which signs the device's calls, and would otherwise inherit
// C:\ProgramData's read access for local users. Applied wherever state is written, not only at
// install, so a device enrolled with `ento agent up` is protected too.
func protectStateDir(dir string) error {
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("protect %s: %w", dir, err)
	}
	return nil
}
