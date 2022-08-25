// Copyright (c) 2022 The Parca Authors
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

package unwind

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"path"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/goburrow/cache"
	"github.com/google/pprof/profile"

	"github.com/parca-dev/parca-agent/internal/dwarf/frame"

	"github.com/parca-dev/parca-agent/pkg/buildid"
)

type MappingCache interface {
	MappingForPID(pid int) ([]*profile.Mapping, error)
}

// TODO(kakkoyun): Can we speed parsing using or look up using .eh_frame_hdr?

// PlanTableBuilder helps to build PlanTable for a given PID.
type PlanTableBuilder struct {
	logger       log.Logger
	mappingCache MappingCache
	fdeCache     cache.Cache
}

func NewPlanTableBuilder(logger log.Logger, mappingCache MappingCache) *PlanTableBuilder {
	// TODO(kakkoyun): Find a logical cache size.
	return &PlanTableBuilder{logger: logger, mappingCache: mappingCache, fdeCache: cache.New(cache.WithMaximumSize(128))}
}

type PlanTable []PlanTableRow

func (t PlanTable) Len() int           { return len(t) }
func (t PlanTable) Less(i, j int) bool { return t[i].Loc < t[j].Loc }
func (t PlanTable) Swap(i, j int)      { t[i], t[j] = t[j], t[i] }

func (ptb *PlanTableBuilder) PlanTableForPid(pid int) (PlanTable, error) {
	mappings, err := ptb.mappingCache.MappingForPID(pid)
	if err != nil {
		return nil, err
	}

	if len(mappings) == 0 {
		return nil, fmt.Errorf("no mapping found for pid %d", pid)
	}

	res := PlanTable{}
	for _, m := range mappings {
		if m.BuildID == "" || m.File == "[vdso]" || m.File == "[vsyscall]" {
			continue
		}

		abs := path.Join(fmt.Sprintf("/proc/%d/root", pid), m.File)
		fdes, err := ptb.readFDEs(abs, m.Start)
		if err != nil {
			level.Debug(ptb.logger).Log("msg", "failed to read frame description entries", "obj", abs, "err", err)
			continue
		}

		res = append(res, buildTable(fdes, m.Start)...)
	}
	return res, nil
}

func registerToString(reg uint64) string {
	// TODO(javierhonduco):
	// - add source for this table
	// - and check architecture, right now this is hardcoded and only x86-64 is supported
	x86_64_regs := []string{
		"rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15", "rip", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
		"xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14", "xmm15",
		"st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7", "mm0", "mm1", "mm2", "mm3",
		"mm4", "mm5", "mm6", "mm7", "rflags", "es", "cs", "ss", "ds", "fs", "gs",
		"unused1", "unused2", "fs.base", "gs.base", "unused3", "unused4", "tr", "ldtr",
		"mxcsr", "fcw", "fsw",
	}

	return x86_64_regs[reg]

}

// PrintTable is a debugging helper that prints the unwinding table to the given io.Writer.
func (ptb *PlanTableBuilder) PrintTable(writer io.Writer, path string, filterNops bool) error {
	fdes, err := ptb.readFDEs(path, 0)
	if err != nil {
		return err
	}

	for _, fde := range fdes {
		fmt.Fprintf(writer, "=> Function start: %x, Function end: %x\n", fde.Begin(), fde.End())
		tableRows := buildTableRows(fde, 0)
		fmt.Fprintf(writer, "\t(found %d rows)\n", len(tableRows))
		for _, tableRow := range tableRows {
			reg := registerToString(tableRow.RSP.Reg)
			fmt.Fprintf(writer, "\t Loc: %x CFA: $%s=%d\n", tableRow.Loc, reg, tableRow.RSP.Offset)
		}
	}

	return nil
}

func (ptb *PlanTableBuilder) readFDEs(path string, start uint64) (frame.FrameDescriptionEntries, error) {
	buildID, err := buildid.BuildID(path)
	if err != nil {
		return nil, err
	}

	if fde, ok := ptb.fdeCache.GetIfPresent(buildID); ok {
		v, ok := fde.(frame.FrameDescriptionEntries)
		if !ok {
			return nil, fmt.Errorf("invalid type of cached FDEs")
		}
		return v, nil
	}

	obj, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open elf: %w", err)
	}
	defer obj.Close()

	sec := obj.Section(".eh_frame")
	if sec == nil {
		return nil, fmt.Errorf("failed to find .eh_frame section")
	}

	// TODO(kakkoyun): Consider using the debug_frame section as a fallback.
	// unwind, err := obj.Section(".debug_frame").Data()

	// TODO(kakkoyun): Needs to support DWARF64 as well.

	ehFrame, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read .eh_frame section: %w", err)
	}

	// TODO(kakkoyun): Byte order of a DWARF section can be different.

	// TODO(kakkoyun): What does actually "start" mark? Start of the .text section? Or the base address of the mapping?
	fde, err := frame.Parse(ehFrame, obj.ByteOrder, start, pointerSize(obj.Machine), sec.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse frame data: %w", err)
	}

	ptb.fdeCache.Put(buildID, fde)
	return fde, nil
}

func buildTable(fdes frame.FrameDescriptionEntries, start uint64) PlanTable {
	table := make(PlanTable, 0, len(fdes))
	for _, fde := range fdes {
		table = append(table, buildTableRows(fde, start)[0])
	}
	// TODO(kakkayun): Print table and debug.
	// TODO(kakkayun): Comparison against readelf -wF and llvm-dwarfdump --eh-frame.

	// Using tests!
	return table
}

// PlanTableRow represents a single row in the plan table.
// x86_64: rip (instruction pointer register), rsp (stack pointer register), rbp (base pointer/frame pointer register)
// aarch64: lr, sp, fp
type PlanTableRow struct {
	// The address of the machine instruction.
	// Each row covers a range of machine instruction, from its address (Loc) to that of the row below.
	Loc uint64
	// Instruction to unwind "rip" register.
	RIP Instruction
	// Instruction to unwind "rsp" register.
	RSP Instruction
	//
	RBP Instruction
	// Raw instruction  for debugging purposes.
	Instruction byte
}

// TODO(kakkoyun): Maybe use CFA and RA for the field names.

// Op represents an operation to identify the unwind calculation that needs to be done,
// - to calculate address of the given register.
type Op uint8

const (
	// This type of register is not supported.
	OpUnimplemented Op = iota
	// Undefined register. The value will be defined at some later IP in the same DIE.
	OpUndefined
	// Value stored at some offset from "CFA".
	OpCFAOffset
	// Value of a machine register plus offset.
	OpRegister
)

// Instruction represents an instruction to unwind the address of a register.
type Instruction struct {
	Op     Op
	Reg    uint64
	Offset int64
}

func (i Instruction) Bytes(order binary.ByteOrder) ([]byte, error) {
	buf := new(bytes.Buffer)
	data := []interface{}{
		uint8(i.Op),
		i.Reg,
		i.Offset,
	}
	for _, v := range data {
		if err := binary.Write(buf, order, v); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func buildTableRows(fde *frame.DescriptionEntry, start uint64) []PlanTableRow {
	rows := make([]PlanTableRow, 0)

	frameContext := frame.ExecuteDwarfProgram(fde)

	instructionContexts := frameContext.GetAllInstructionContexts()

	for _, instructionContext := range instructionContexts {
		// We kinda now the offset to the return address
		rule, found := instructionContext.Regs[instructionContext.RetAddrReg]

		row := PlanTableRow{
			Loc: start + instructionContext.Loc(),
		}

		if found {
			// nolint:exhaustive
			switch rule.Rule {
			case frame.RuleOffset:
				row.RIP = Instruction{Op: OpCFAOffset, Offset: rule.Offset}
			case frame.RuleUndefined:
				row.RIP = Instruction{Op: OpUndefined}
			default:
				row.RIP = Instruction{Op: OpUnimplemented}
			}
		} else {
			row.RIP = Instruction{Op: OpUnimplemented}
		}

		// Not quite, we might need to apply an offset either $rsp or $rbp
		row.RSP = Instruction{Op: OpRegister, Reg: instructionContext.CFA.Reg, Offset: instructionContext.CFA.Offset}

		rows = append(rows, row)

	}
	return rows
}

func pointerSize(arch elf.Machine) int {
	//nolint:exhaustive
	switch arch {
	case elf.EM_386:
		return 4
	case elf.EM_AARCH64, elf.EM_X86_64:
		return 8
	default:
		return 0
	}
}