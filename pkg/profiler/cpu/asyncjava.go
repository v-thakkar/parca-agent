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

package profiler

import (
	"context"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/parca-dev/parca-agent/pkg/arguments"
	"github.com/parca-dev/parca-agent/pkg/profiler"
)

type JavaCPU struct {
	logger                     log.Logger
	profilingDuration          time.Duration
	profilingSamplingFrequency arguments.SetInterval
	labelsManager              profiler.LabelsManager

	mtx *sync.RWMutex
	// Reporting.
	lastError                      error
	lastSuccessfulProfileStartedAt time.Time
	lastProfileStartedAt           time.Time
}

func NewJavaProfiler(
	logger log.Logger,
	profileWriter profiler.ProfileWriter,
	labelsManager profiler.LabelsManager,
	// Maps to async profiler option (TODO)
	profilingDuration args.Duration,
	profilingSamplingFrequency arguments.SetInterval,
) *JavaCPU {
	return &JavaCPU{
		logger:                     logger,
		profileWriter:              profileWriter,
		labelsManager:              labelsManager,
		profilingDuration:          profilingDuration,
		profilingSamplingFrequency: profilingSamplingFrequency,

		mtx: &sync.RWMutex{},
	}
}

func (p *JavaCPU) Name() string {
	return "parca-agent-java-async-profiler"
}

func (p *JavaCPU) Run(_ context.Context) error {
	level.Debug(p.logger).Log("msg", "starting async-profiler for java processes")

	args := arguments.NewArguments()
	defer args.DeleteArguments()

	samplingPeriod := int64(1e9 / p.profilingSamplingFrequency)
	args.SetInterval(samplingPeriod)

	// Set the actions and the duration

	// Start the profiling loop
	level.Debug(p.logger).Log("msg", "start the profiling loop")

}

func (p *JavaCPU) Stop() {

}

func (p *JavaCPU) LastProfileStartedAt() time.Time {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastProfileStartedAt
}

func (p *JavaCPU) LastError() error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.lastError
}

/* func (p *JavaCPU) ProcessLastErrors() map[int]error {
	p.mtx.RLock()
	defer p.mtx.RUnlock()
	return p.processLastErrors
} */

func (p *JavaCPU) obtainProfiles(ctx context.Context) ([]*profiler.Profile, error) {
	// From the jfr to pprof converter
}
