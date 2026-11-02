package agent

import (
	"bufio"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// Parsers of what the systems' own tools print, kept apart from the collectors (posture_*.go) so
// that they are tested on every system. Each returns nil when the output says nothing it knows:
// unknown, never a guess.

func boolPtr(b bool) *bool { return &b }

// parseFdesetup reads `fdesetup status` (macOS): "FileVault is On." or "FileVault is Off.", the
// former also while encryption is still in progress.
func parseFdesetup(out string) *bool {
	switch {
	case strings.Contains(out, "FileVault is On"):
		return boolPtr(true)
	case strings.Contains(out, "FileVault is Off"):
		return boolPtr(false)
	}
	return nil
}

// parseSocketFilterFW reads `socketfilterfw --getglobalstate` (macOS): "Firewall is enabled.
// (State = 1)", "Firewall is disabled. (State = 0)", or block-all (State = 2).
func parseSocketFilterFW(out string) *bool {
	if _, after, ok := strings.Cut(out, "State = "); ok && after != "" {
		switch after[0] {
		case '1', '2':
			return boolPtr(true)
		case '0':
			return boolPtr(false)
		}
	}
	switch {
	case strings.Contains(out, "is enabled") || strings.Contains(out, "blocking all"):
		return boolPtr(true)
	case strings.Contains(out, "is disabled"):
		return boolPtr(false)
	}
	return nil
}

// parseSwVers reads `sw_vers -productVersion` (macOS): "14.5".
func parseSwVers(out string) string {
	v := strings.TrimSpace(out)
	if v == "" || strings.ContainsFunc(v, func(r rune) bool { return !(r >= '0' && r <= '9' || r == '.') }) {
		return ""
	}
	return v
}

// parseBitLocker reads the lines "<drive letter>=<ProtectionStatus>" printed for every
// Win32_EncryptableVolume (Windows) and returns the protection of drive ("C:"): 1 on, 0 off, 2
// unknown (a locked volume).
func parseBitLocker(out, drive string) *bool {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		letter, status, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(letter), drive) {
			continue
		}
		switch strings.TrimSpace(status) {
		case "1":
			return boolPtr(true)
		case "0":
			return boolPtr(false)
		}
		return nil
	}
	return nil
}

// parseManageBDE reads `manage-bde -status C:` (Windows, English): "Protection Status:
// Protection On".
func parseManageBDE(out string) *bool {
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		label, value, ok := strings.Cut(sc.Text(), ":")
		if !ok || strings.TrimSpace(label) != "Protection Status" {
			continue
		}
		switch strings.TrimSpace(value) {
		case "Protection On":
			return boolPtr(true)
		case "Protection Off":
			return boolPtr(false)
		}
	}
	return nil
}

// firewallProfile is one Windows Firewall profile's EnableFirewall value: from group policy (which
// wins) and from the local settings; nil where the value is not set.
type firewallProfile struct {
	Policy, Local *uint32
}

// windowsFirewallOn reports whether every profile (domain, private, public) is on: off as soon as
// one is, unknown when one is not set anywhere and none is off.
func windowsFirewallOn(profiles []firewallProfile) *bool {
	unknown := len(profiles) == 0
	for _, p := range profiles {
		v := p.Policy
		if v == nil {
			v = p.Local
		}
		switch {
		case v == nil:
			unknown = true
		case *v == 0:
			return boolPtr(false)
		}
	}
	if unknown {
		return nil
	}
	return boolPtr(true)
}

// nftChain is what decides whether an nftables chain filters what reaches the device.
type nftChain struct {
	InputHook  bool // a base chain at the input hook
	PolicyDrop bool
	EndsInDrop bool // its last rule drops or rejects whatever reaches it
}

// linuxFirewallOn reports whether the input path filters: a base chain at the input hook that drops
// by default, or whose last rule drops or rejects everything the rules before it did not accept
// (firewalld). Rules that drop some packets only (fail2ban's, "ct state invalid drop") in a chain
// that accepts the rest do not count. listed is false when the chains could not be read.
func linuxFirewallOn(chains []nftChain, listed bool) *bool {
	if !listed {
		return nil
	}
	for _, c := range chains {
		if c.InputHook && (c.PolicyDrop || c.EndsInDrop) {
			return boolPtr(true)
		}
	}
	return boolPtr(false)
}

// parseNftChainJSON reads `nft -j list chain FAMILY TABLE CHAIN`: whether the chain's last rule
// drops or rejects everything that reaches it, by the rule of dropsAll (only counters and logs
// besides the verdict). It is the fallback where google/nftables cannot decode a rule of the chain.
func parseNftChainJSON(out string) (bool, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		return false, err
	}
	var last []map[string]json.RawMessage
	seen := false
	for _, item := range doc.Nftables {
		raw, ok := item["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Expr []map[string]json.RawMessage `json:"expr"`
		}
		if err := json.Unmarshal(raw, &rule); err != nil {
			return false, err
		}
		last, seen = rule.Expr, true
	}
	if !seen {
		if len(doc.Nftables) == 0 {
			return false, errors.New("no chain in the output")
		}
		return false, nil
	}
	verdict := false
	for _, e := range last {
		for k, v := range e {
			switch k {
			case "counter", "log":
			case "drop", "reject":
				verdict = true
			case "xt": // iptables-nft's REJECT
				var xt struct{ Type, Name string }
				if json.Unmarshal(v, &xt) != nil || xt.Type != "target" || xt.Name != "REJECT" {
					return false, nil
				}
				verdict = true
			default:
				return false, nil
			}
		}
	}
	return verdict, nil
}

// parseIptablesInput reads `iptables -S INPUT` (the legacy backend): "-P INPUT DROP", or a last
// rule that drops or rejects everything ("-A INPUT -j REJECT --reject-with icmp-host-prohibited");
// rules that match something drop some packets only.
func parseIptablesInput(out string) *bool {
	sc := bufio.NewScanner(strings.NewReader(out))
	seen, last := false, []string(nil)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || f[1] != "INPUT" {
			continue
		}
		seen = true
		if f[0] == "-P" && f[2] == "DROP" {
			return boolPtr(true)
		}
		if f[0] == "-A" {
			last = f
		}
	}
	if !seen {
		return nil
	}
	if len(last) >= 4 && (last[2] == "-j" || last[2] == "--jump") {
		switch {
		case last[3] == "DROP" && len(last) == 4,
			last[3] == "REJECT" && (len(last) == 4 || len(last) == 6 && last[4] == "--reject-with"):
			return boolPtr(true)
		}
	}
	return boolPtr(false)
}

// parseOSRelease reads os-release(5): "<ID> <VERSION_ID>", like "debian 12".
func parseOSRelease(content string) string {
	vals := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if u, err := strconv.Unquote(v); err == nil {
			v = u
		} else {
			v = strings.Trim(v, `'"`)
		}
		vals[k] = v
	}
	return strings.TrimSpace(vals["ID"] + " " + vals["VERSION_ID"])
}

// antimalwareScript prints, for the antivirus products registered with Windows Security (Security
// Center, client editions), "av=<productState>" each; where there are none (server editions),
// Microsoft Defender's "defender=<AntivirusEnabled>,<RealTimeProtectionEnabled>".
const antimalwareScript = `$p = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue); if ($p.Count -gt 0) { $p | ForEach-Object { 'av={0}' -f $_.productState } } else { $s = Get-MpComputerStatus -ErrorAction SilentlyContinue; if ($s) { 'defender={0},{1}' -f $s.AntivirusEnabled, $s.RealTimeProtectionEnabled } }`

// parseAntimalware reads antimalwareScript's output: on when a registered product has real-time
// protection on (bit 0x1000 of its productState) or Defender reports both enabled; off when the
// products or Defender say otherwise; unknown when nothing was printed.
func parseAntimalware(out string) *bool {
	var seen, on bool
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "av="):
			state, err := strconv.ParseUint(strings.TrimPrefix(line, "av="), 10, 32)
			if err != nil {
				continue
			}
			seen = true
			on = on || state&0x1000 != 0
		case strings.HasPrefix(line, "defender="):
			seen = true
			on = on || strings.EqualFold(strings.TrimPrefix(line, "defender="), "True,True")
		}
	}
	if !seen {
		return nil
	}
	return boolPtr(on)
}

// linuxScanners are the process names (/proc/<pid>/comm, at most 15 characters) of real-time
// anti-malware scanners for Linux: ClamAV's on-access scanner, Microsoft Defender for Endpoint,
// CrowdStrike Falcon, SentinelOne, Sophos, Trend Micro Deep Security, Bitdefender GravityZone.
var linuxScanners = []string{"clamonacc", "wdavdaemon", "falcon-sensor", "s1-agent", "sophos_threat_d", "ds_agent", "bdsecd"}

// linuxAntimalware: on when one of linuxScanners runs; unknown otherwise (a product it does not
// know may be running).
func linuxAntimalware(comms []string) *bool {
	for _, c := range comms {
		for _, s := range linuxScanners {
			if strings.TrimSpace(c) == s {
				return boolPtr(true)
			}
		}
	}
	return nil
}
