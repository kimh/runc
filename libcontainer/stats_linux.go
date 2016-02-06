package libcontainer

import "github.com/kimh/runc/libcontainer/cgroups"

type Stats struct {
	Interfaces  []*NetworkInterface
	CgroupStats *cgroups.Stats
}
