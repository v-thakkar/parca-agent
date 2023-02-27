// Copyright 2022-2023 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package hsperfdata

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/go-kit/log"
	"github.com/parca-dev/parca-agent/pkg/perf"
)

const hsperfdata = "/tmp/hsperfdata_*"

type Cache struct {
	pids   map[int]bool
	fs     fs.FS
	logger log.Logger
	mu     sync.Mutex
	nsPID  map[int]int
}

type realfs struct{}

func (f *realfs) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func NewCache(logger log.Logger) *Cache {
	return &Cache{
		pids:   make(map[int]bool),
		fs:     &realfs{},
		logger: logger,
		nsPID:  map[int]int{},
	}
}

// IsJavaProcess returns true if the hsperfdata file exists for a given pid.
// It first searches in all hsperfdata user directories for the processes
// running on host and then searches in /proc/{pid}/root/tmp for processes
// running in containers. Note that pids are assumed to be unique regardless
// of username.

func (c *Cache) IsJavaProcess(pid int) (bool, error) {
	// Check if the pid is in the cache
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.pids[pid]; ok {
		return true, nil
	}

	// List all directories that match the pattern /tmp/hsperfdata_*
	dirs, err := filepath.Glob(hsperfdata)
	if err != nil {
		return false, fmt.Errorf("failed to list directories: %w", err)
	}

	// Loop over all directories and search for the hsperfdata file for the given pid
	for _, dir := range dirs {
		hsperfdataPath := filepath.Join(dir, strconv.Itoa(pid))
		if _, err := c.fs.Open(hsperfdataPath); err == nil {
			c.pids[pid] = true
			return true, nil
		}
	}

	// Check if pid has nsPid attached to it
	nsPid, found := c.nsPID[pid]
	if !found {
		nsPids, err := perf.FindNSPIDs(c.fs, pid)
		if err != nil {
			if os.IsNotExist(err) {
				return false, fmt.Errorf("%w when reading status", perf.ErrProcNotFound)
			}
			return false, err
		}

		c.nsPID[pid] = nsPids[len(nsPids)-1]
		nsPid = c.nsPID[pid]
	}

	// TODO(vthakkar): Check for the process mount point.
	perfdataFiles := fmt.Sprintf("/proc/%d/root/tmp/", pid)

	files, err := ioutil.ReadDir(perfdataFiles)
	if err != nil {
		return false, fmt.Errorf("error reading %s: %v", perfdataFiles, err)
	}
	for _, f := range files {
		if f.IsDir() {
			if name := f.Name(); strings.HasPrefix(name, hsperfdata) {
				if strings.HasSuffix(name, strconv.Itoa(pid)) || strings.HasSuffix(name, strconv.Itoa(nsPid)) {
					c.pids[pid] = true
					return true, nil
				}
			}
		}
	}

	c.pids[pid] = false
	return false, nil
}
