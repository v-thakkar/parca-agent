package profiler

/*
#cgo LDFLAGS: -ldl-L/../asyncprofiler/build/libasyncprofiler.so -lasyncprofiler
#include <stdlib.h>
#include <arguments.h>
*/
import "C"
import (
	"errors"
)

// This package has Golang API that serves as a wrapper around native async profiler library

type AsyncProfiler struct{}

func (p *AsyncProfiler) Start(action string, interval int64) error {
	if action == "" {
		return errors.New("action is empty")
	}

	C.argumentsStart(C.CString(action), C.jlong(action))
	return nil
}

func (p *AsyncProfiler) Resume(action string, interval int64) error {
	if action == "" {
		return errors.New("action is empty")
	}

	C.argumentsResume(C.CString(action), C.jlong(action))
	return nil
}

func (p *AsyncProfiler) Stop() error {
	C.argumentsStop()
	return nil
}

func (p *AsyncProfiler) CollectSamples() int64 {
	return int64(C.argumentsGetSamples())
}
