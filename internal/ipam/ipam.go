// Package ipam lays out the overlay address space of a deployment.
//
// The overlay network is an IPv4 /16. The first /24 is reserved for control nodes, the last /24 for
// the temporary addresses of enrollment tokens, and peers get the addresses in between.
package ipam

import (
	"errors"
	"fmt"
	"net/netip"
)

// Space is the overlay address space of a deployment.
type Space struct {
	Prefix netip.Prefix
}

// New validates an overlay network prefix.
func New(prefix netip.Prefix) (Space, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || prefix.Bits() != 16 {
		return Space{}, fmt.Errorf("overlay network must be an IPv4 /16, got %s", prefix)
	}
	return Space{Prefix: prefix}, nil
}

func (s Space) addr(third, fourth int) netip.Addr {
	b := s.Prefix.Addr().As4()
	b[2], b[3] = byte(third), byte(fourth)
	return netip.AddrFrom4(b)
}

// ControlAddresses returns the addresses reserved for control nodes, in allocation order.
func (s Space) ControlAddresses() []netip.Addr {
	out := make([]netip.Addr, 0, 254)
	for i := 1; i <= 254; i++ {
		out = append(out, s.addr(0, i))
	}
	return out
}

// EnrollmentAddresses returns the addresses reserved for enrollment tokens, in allocation order.
func (s Space) EnrollmentAddresses() []netip.Addr {
	out := make([]netip.Addr, 0, 254)
	for i := 1; i <= 254; i++ {
		out = append(out, s.addr(255, i))
	}
	return out
}

// IsEnrollment reports whether a belongs to the enrollment range.
func (s Space) IsEnrollment(a netip.Addr) bool {
	return s.Prefix.Contains(a) && a.As4()[2] == 255
}

// IsControl reports whether a belongs to the control node range.
func (s Space) IsControl(a netip.Addr) bool {
	return s.Prefix.Contains(a) && a.As4()[2] == 0
}

// ErrExhausted is returned when a range has no free address left.
var ErrExhausted = errors.New("address range exhausted")

// FirstFree returns the first address of candidates that is not in used.
func FirstFree(candidates []netip.Addr, used map[netip.Addr]bool) (netip.Addr, error) {
	for _, a := range candidates {
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, ErrExhausted
}

// FirstFreePeer returns the first free peer address.
func (s Space) FirstFreePeer(used map[netip.Addr]bool) (netip.Addr, error) {
	for third := 1; third <= 254; third++ {
		for fourth := 1; fourth <= 254; fourth++ {
			if a := s.addr(third, fourth); !used[a] {
				return a, nil
			}
		}
	}
	return netip.Addr{}, ErrExhausted
}
