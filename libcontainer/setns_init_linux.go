// +build linux

package libcontainer

import (
	"os"

	"github.com/kimh/runc/libcontainer/apparmor"
	"github.com/kimh/runc/libcontainer/keys"
	"github.com/kimh/runc/libcontainer/label"
	"github.com/kimh/runc/libcontainer/seccomp"
	"github.com/kimh/runc/libcontainer/system"
)

// linuxSetnsInit performs the container's initialization for running a new process
// inside an existing container.
type linuxSetnsInit struct {
	config *initConfig
}

func (l *linuxSetnsInit) Init() error {
	// do not inherit the parent's session keyring
	if _, err := keyctl.JoinSessionKeyring("_ses"); err != nil {
		return err
	}
	if err := setupRlimits(l.config.Config); err != nil {
		return err
	}
	if err := setOomScoreAdj(l.config.Config.OomScoreAdj); err != nil {
		return err
	}
	if l.config.Config.Seccomp != nil {
		if err := seccomp.InitSeccomp(l.config.Config.Seccomp); err != nil {
			return err
		}
	}
	if err := finalizeNamespace(l.config); err != nil {
		return err
	}
	if err := apparmor.ApplyProfile(l.config.Config.AppArmorProfile); err != nil {
		return err
	}
	if l.config.Config.ProcessLabel != "" {
		if err := label.SetProcessLabel(l.config.Config.ProcessLabel); err != nil {
			return err
		}
	}
	return system.Execv(l.config.Args[0], l.config.Args[0:], os.Environ())
}
