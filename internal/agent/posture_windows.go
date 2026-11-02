//go:build windows

package agent

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"entowire.com/ento/internal/api"
)

// collectPlatform finds out the posture of a Windows system: its version with build and revision
// (RtlGetVersion, registry UBR), BitLocker on the system drive (WMI, else manage-bde), whether
// every firewall profile is on and UEFI Secure Boot (registry), and whether an antivirus has
// real-time protection on (Windows Security, else Microsoft Defender). Screen lock stays unknown.
func collectPlatform(ctx context.Context) api.Posture {
	p := api.Posture{OS: "windows"}
	v := windows.RtlGetVersion()
	ubr, _ := regDWORD(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "UBR")
	p.OSVersion = fmt.Sprintf("%d.%d.%d", v.MajorVersion, v.MinorVersion, v.BuildNumber)
	if ubr != nil {
		p.OSVersion += fmt.Sprintf(".%d", *ubr)
	}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		edition, _, _ := k.GetStringValue("EditionID")
		display, _, _ := k.GetStringValue("DisplayVersion")
		k.Close()
		p.Distribution = strings.TrimSpace(edition + " " + display)
	}
	p.DiskEncryption = bitLocker(ctx)
	p.Firewall = windowsFirewall()
	p.SecureBoot = windowsSecureBoot()
	p.Antimalware = windowsAntimalware(ctx)
	return p
}

func windowsAntimalware(ctx context.Context) *bool {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil
	}
	out, err := runFixed(ctx, filepath.Join(sys, `WindowsPowerShell\v1.0\powershell.exe`), "-NoProfile", "-NonInteractive", "-Command", antimalwareScript)
	if err != nil {
		return nil
	}
	return parseAntimalware(out)
}

// regDWORD reads a DWORD under HKLM; nil when it is not set (or not readable).
func regDWORD(path, name string) (*uint32, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return nil, err
	}
	x := uint32(v)
	return &x, nil
}

// systemDrive is the drive Windows runs from ("C:").
func systemDrive() string {
	dir, err := windows.GetSystemWindowsDirectory()
	if err != nil || len(dir) < 2 || dir[1] != ':' {
		return "C:"
	}
	return strings.ToUpper(dir[:2])
}

// bitLockerScript prints "<drive letter>=<ProtectionStatus>" for every encryptable volume.
const bitLockerScript = `Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume | ForEach-Object { '{0}={1}' -f $_.DriveLetter, $_.ProtectionStatus }`

func bitLocker(ctx context.Context) *bool {
	sys, err := windows.GetSystemDirectory()
	if err != nil {
		return nil
	}
	drive := systemDrive()
	ps := filepath.Join(sys, `WindowsPowerShell\v1.0\powershell.exe`)
	if out, err := runFixed(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", bitLockerScript); err == nil {
		if on := parseBitLocker(out, drive); on != nil {
			return on
		}
	}
	if out, err := runFixed(ctx, filepath.Join(sys, "manage-bde.exe"), "-status", drive); err == nil {
		return parseManageBDE(out)
	}
	return nil
}

// windowsFirewall reads EnableFirewall of the domain, private and public profiles, group policy
// first.
func windowsFirewall() *bool {
	const (
		policy = `SOFTWARE\Policies\Microsoft\WindowsFirewall\`
		local  = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	)
	var profiles []firewallProfile
	for _, pr := range [][2]string{{"DomainProfile", "DomainProfile"}, {"PrivateProfile", "StandardProfile"}, {"PublicProfile", "PublicProfile"}} {
		var fp firewallProfile
		fp.Policy, _ = regDWORD(policy+pr[0], "EnableFirewall")
		fp.Local, _ = regDWORD(local+pr[1], "EnableFirewall")
		profiles = append(profiles, fp)
	}
	return windowsFirewallOn(profiles)
}

// windowsSecureBoot reads UEFISecureBootEnabled: a system without the key boots without UEFI
// Secure Boot.
func windowsSecureBoot() *bool {
	v, err := regDWORD(`SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled")
	switch {
	case errors.Is(err, registry.ErrNotExist):
		return boolPtr(false)
	case err != nil:
		return nil
	}
	return boolPtr(*v == 1)
}
