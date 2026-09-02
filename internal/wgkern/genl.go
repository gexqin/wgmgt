package wgkern

import (
	"encoding/binary"
	"fmt"
	"math"
	"syscall"

	"golang.org/x/sys/unix"
)

// Generic netlink constants (stable UAPI).
const (
	genlIDCtrl         = 0x10 // GENL_ID_CTRL
	ctrlCmdGetFamily   = 3    // CTRL_CMD_GETFAMILY
	ctrlAttrFamilyName = 2    // CTRL_ATTR_FAMILY_NAME
)

// genlFamilyGet resolves a generic-netlink family by name. It returns an
// error (ENOENT when the family does not exist), which for "wireguard"
// means no kernel module is providing it.
func genlFamilyGet(fd int, name string) error {
	name += "\x00"
	attrLen := 4 + len(name)
	msgLen := unix.NLMSG_HDRLEN + 4 + align4(attrLen) // nlmsghdr + genlmsghdr + nlattr
	if attrLen > math.MaxUint16 || uint64(msgLen) > math.MaxUint32 {
		return fmt.Errorf("generic netlink family name is too long")
	}

	buf := make([]byte, msgLen)
	binary.NativeEndian.PutUint32(buf[0:4], uint32(msgLen)) // #nosec G115 -- checked above
	binary.NativeEndian.PutUint16(buf[4:6], genlIDCtrl)     // nlmsg_type
	binary.NativeEndian.PutUint16(buf[6:8], unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(buf[12:16], 1) // nlmsg_seq
	buf[unix.NLMSG_HDRLEN] = ctrlCmdGetFamily
	buf[unix.NLMSG_HDRLEN+1] = 1 // version

	off := unix.NLMSG_HDRLEN + 4                                   // genlmsghdr size
	binary.NativeEndian.PutUint16(buf[off:off+2], uint16(attrLen)) // #nosec G115 -- checked above
	binary.NativeEndian.PutUint16(buf[off+2:off+4], ctrlAttrFamilyName)
	copy(buf[off+4:], name)

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(fd, buf, 0, sa); err != nil {
		return err
	}

	resp := make([]byte, 4096)
	n, _, err := unix.Recvfrom(fd, resp, 0)
	if err != nil {
		return err
	}
	resp = resp[:n]
	if len(resp) < unix.NLMSG_HDRLEN {
		return fmt.Errorf("short generic netlink response")
	}

	if binary.NativeEndian.Uint16(resp[4:6]) == unix.NLMSG_ERROR {
		if len(resp) < unix.NLMSG_HDRLEN+4 {
			return fmt.Errorf("short generic netlink error response")
		}
		if rawCode := binary.NativeEndian.Uint32(resp[unix.NLMSG_HDRLEN:]); rawCode != 0 {
			magnitude := ^rawCode + 1                // kernel encodes -errno as a signed int32
			return syscall.Errno(uintptr(magnitude)) // #nosec G115 -- uintptr is at least 32 bits on supported Linux targets
		}
	}
	return nil
}

func align4(n int) int { return (n + 3) &^ 3 }
