//go:build windows

// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2025-2026 Shaun Murphy

package securefs

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	localSystemSID    = "S-1-5-18"
	administratorsSID = "S-1-5-32-544"
	creatorOwnerSID   = "S-1-3-0"
	ownerRightsSID    = "S-1-3-4"
)

func verifyPrivateFile(file *os.File) error {
	return verifyWindowsACL(file, false)
}

func securePrivateFile(file *os.File) error {
	if err := setPrivateWindowsACL(file, false); err != nil {
		return err
	}
	return verifyWindowsACL(file, false)
}

func verifyOrSecurePrivateDirectory(path, purpose string, _ os.FileInfo, created bool) error {
	file, err := openFileNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	linked, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !opened.IsDir() || !linked.IsDir() || linked.Mode()&os.ModeSymlink != 0 || !os.SameFile(opened, linked) {
		return fmt.Errorf("%s directory is not a stable secure directory: %s", purpose, path)
	}
	if created {
		if err := setPrivateWindowsACL(file, true); err != nil {
			return fmt.Errorf("secure %s directory: %w", purpose, err)
		}
	}
	if err := verifyWindowsACL(file, true); err != nil {
		return fmt.Errorf("insecure %s directory %s: %w", purpose, path, err)
	}
	return nil
}

func setPrivateWindowsACL(file *os.File, directory bool) error {
	securityFile, err := openWindowsSecurityHandle(file.Name(), directory, true)
	if err != nil {
		return fmt.Errorf("open DACL handle: %w", err)
	}
	defer func() { _ = securityFile.Close() }()
	originalInfo, err := file.Stat()
	if err != nil {
		return err
	}
	securityInfo, err := securityFile.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(originalInfo, securityInfo) {
		return fmt.Errorf("private file changed while securing its DACL: %s", file.Name())
	}
	if err := verifyWindowsOwner(securityFile); err != nil {
		return err
	}
	userSID, err := currentWindowsUserSID()
	if err != nil {
		return err
	}
	inheritance := ""
	if directory {
		inheritance = "OICI"
	}
	sddl := fmt.Sprintf("D:P(A;%s;FA;;;%s)(A;%s;FA;;;SY)(A;%s;FA;;;BA)",
		inheritance, userSID.String(), inheritance, inheritance)
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("build private DACL: %w", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		if err == nil {
			err = windows.ERROR_INVALID_ACL
		}
		return fmt.Errorf("build private DACL: %w", err)
	}
	err = windows.SetSecurityInfo(
		windows.Handle(securityFile.Fd()),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	)
	if err != nil {
		return fmt.Errorf("apply private DACL: %w", err)
	}
	return nil
}

func verifyWindowsOwner(file *os.File) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read owner: %w", err)
	}
	if descriptor == nil {
		return fmt.Errorf("owner is unavailable")
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		if err == nil {
			err = windows.ERROR_INVALID_OWNER
		}
		return fmt.Errorf("read owner: %w", err)
	}
	trusted, err := trustedWindowsOwnerSIDs()
	if err != nil {
		return err
	}
	if !sidIn(owner, trusted) {
		return fmt.Errorf("owner %s is not the current account or a trusted system administrator", owner.String())
	}
	return nil
}

// openWindowsSecurityHandle asks for the rights SetSecurityInfo actually
// requires. A normal os.OpenFile handle has GENERIC_READ/WRITE but not
// WRITE_DAC, even when the caller owns the object.
func openWindowsSecurityHandle(path string, directory, writeDACL bool) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	access := uint32(windows.READ_CONTROL)
	if writeDACL {
		access |= windows.WRITE_DAC
	}
	attributes := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		attributes |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		attributes,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func verifyWindowsACL(file *os.File, directory bool) error {
	descriptor, err := windows.GetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("read owner/DACL: %w", err)
	}
	if descriptor == nil {
		return fmt.Errorf("owner/DACL is unavailable")
	}
	trustedOwners, err := trustedWindowsOwnerSIDs()
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		if err == nil {
			err = windows.ERROR_INVALID_OWNER
		}
		return fmt.Errorf("read owner: %w", err)
	}
	if !sidIn(owner, trustedOwners) {
		return fmt.Errorf("owner %s is not the current account or a trusted system administrator", owner.String())
	}
	trusted, err := trustedWindowsSIDs()
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		if err == nil {
			err = windows.ERROR_INVALID_ACL
		}
		return fmt.Errorf("read DACL: %w", err)
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return fmt.Errorf("read DACL entry %d: %w", index, err)
		}
		if ace == nil {
			return fmt.Errorf("DACL entry %d is unavailable", index)
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			// An inherit-only ACE has no effect on a file, but it matters on a
			// directory because a future state file would inherit the grant.
			if !directory && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
				continue
			}
		default:
			return fmt.Errorf("DACL entry %d uses unsupported ACE type %d", index, ace.Header.AceType)
		}
		if ace.Mask == 0 {
			continue
		}
		// #nosec G103 -- GetAce returns the variable-length SID inline at
		// SidStart; this is the layout required by the native ACCESS_ALLOWED_ACE.
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return fmt.Errorf("DACL entry %d has an invalid SID", index)
		}
		if !sidIn(sid, trusted) {
			return fmt.Errorf("DACL grants access mask %#x to untrusted SID %s", uint32(ace.Mask), sid.String())
		}
	}
	return nil
}

func currentWindowsUserSID() (*windows.SID, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read current process user: %w", err)
	}
	if user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return nil, fmt.Errorf("current process user SID is unavailable")
	}
	return user.User.Sid, nil
}

func trustedWindowsOwnerSIDs() ([]*windows.SID, error) {
	user, err := currentWindowsUserSID()
	if err != nil {
		return nil, err
	}
	system, err := windows.StringToSid(localSystemSID)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.StringToSid(administratorsSID)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{user, system, administrators}, nil
}

func trustedWindowsSIDs() ([]*windows.SID, error) {
	trusted, err := trustedWindowsOwnerSIDs()
	if err != nil {
		return nil, err
	}
	creatorOwner, err := windows.StringToSid(creatorOwnerSID)
	if err != nil {
		return nil, err
	}
	ownerRights, err := windows.StringToSid(ownerRightsSID)
	if err != nil {
		return nil, err
	}
	return append(trusted, creatorOwner, ownerRights), nil
}

func sidIn(candidate *windows.SID, allowed []*windows.SID) bool {
	for _, sid := range allowed {
		if windows.EqualSid(candidate, sid) {
			return true
		}
	}
	return false
}
