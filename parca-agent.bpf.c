// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation
// by the CGO compiler

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see
 * https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8
 * for more details
 */
#include "limits.h"
#include "vmlinux.h"
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#define KBUILD_MODNAME "parca-agent"

#undef container_of
#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#if defined(bpf_target_x86)
#define PT_REGS_PARM6(ctx) ((ctx)->r9)
#elif defined(bpf_target_arm64)
#define PT_REGS_PARM6(x) (((PT_REGS_ARM64 *)(x))->regs[5])
#endif

// Max amount of different stack trace addresses to buffer in the Map
#define MAX_STACK_ADDRESSES 1024
// Max depth of each stack trace to track
#define MAX_STACK_DEPTH 127
// TODO(kakkoyun): Explain.
#define MAX_PID_MAP_SIZE 1024
// TODO(kakkoyun): Explain.
#define DEFAULT_MAX_ENTRIES 10240
// TODO(kakkoyun): Explain.
#define MAX_BINARY_SEARCH_DEPTH 24

#define BPF_MAP(_name, _type, _key_type, _value_type, _max_entries)           \
  struct bpf_map_def SEC ("maps") _name = {                                   \
    .type = _type,                                                            \
    .key_size = sizeof (_key_type),                                           \
    .value_size = sizeof (_value_type),                                       \
    .max_entries = _max_entries,                                              \
  };

// Stack Traces are slightly different
// in that the value is 1 big byte array
// of the stack addresses
#define BPF_STACK_TRACE(_name, _max_entries)                                  \
  struct bpf_map_def SEC ("maps") _name = {                                   \
    .type = BPF_MAP_TYPE_STACK_TRACE,                                         \
    .key_size = sizeof (u32),                                                 \
    .value_size = sizeof (size_t) * MAX_STACK_DEPTH,                          \
    .max_entries = _max_entries,                                              \
  };

#define BPF_HASH(_name, _key_type, _value_type, _max_entries)                 \
  BPF_MAP (_name, BPF_MAP_TYPE_HASH, _key_type, _value_type, _max_entries);

#define BPF_ARRAY(_name, _key_type, _value_type, _max_entries)                \
  BPF_MAP (_name, BPF_MAP_TYPE_ARRAY, _key_type, _value_type, _max_entries);

//// Value size must be u32 because it is inner map id
//#define BPF_PID_HASH_OF_MAP(_name, _max_entries) \
//  struct bpf_map_def SEC ("maps") _name = { \
//    .type = BPF_MAP_TYPE_HASH_OF_MAPS, \
//    .key_size = sizeof (__u32), \
//    .value_size = sizeof (__u32), \
//    .max_entries = _max_entries, \
//  };

/*============================= INTERNAL STRUCTS ============================*/

typedef struct stack_count_key
{
  u32 pid;
  int user_stack_id;
  int kernel_stack_id;
} stack_count_key_t;

typedef struct stack_unwind_instruction
{
  int op;
  u64 reg;
  s64 offset;
} stack_unwind_instruction_t;

/*================================ MAPS =====================================*/

BPF_HASH (config, u32, u32, 1); // TODO(kakkoyun): Remove later.
BPF_HASH (counts, stack_count_key_t, u64, DEFAULT_MAX_ENTRIES);
BPF_STACK_TRACE (stack_traces, MAX_STACK_ADDRESSES);

BPF_ARRAY (pcs, u32, u64, DEFAULT_MAX_ENTRIES);
BPF_ARRAY (rips, u32, stack_unwind_instruction_t, DEFAULT_MAX_ENTRIES);
BPF_ARRAY (rsps, u32, stack_unwind_instruction_t, DEFAULT_MAX_ENTRIES);
BPF_ARRAY (user_stack_traces, u32, u64, MAX_STACK_DEPTH);

// BPF_PID_HASH_OF_MAP (pcs, MAX_PID_MAP_SIZE);
// BPF_PID_HASH_OF_MAP (rips, MAX_PID_MAP_SIZE);
// BPF_PID_HASH_OF_MAP (rsps, MAX_PID_MAP_SIZE);

/*=========================== HELPER FUNCTIONS ==============================*/

static __always_inline void *
bpf_map_lookup_or_try_init (void *map, const void *key, const void *init)
{
  void *val;
  long err;

  val = bpf_map_lookup_elem (map, key);
  if (val)
    return val;

  err = bpf_map_update_elem (map, key, init, BPF_NOEXIST);
  // 17 == EEXIST
  if (err && err != -17)
    return 0;

  return bpf_map_lookup_elem (map, key);
}

// This code gets a bit complex. Probably not suitable for casual hacking.
SEC ("perf_event")
int
do_sample (struct bpf_perf_event_data *ctx)
{
  u64 id = bpf_get_current_pid_tgid ();
  u32 tgid = id >> 32;
  u32 pid = id;

  if (pid == 0)
    return 0;

  // create map key
  stack_count_key_t key = { .pid = tgid };

  // get user stack
  u32 index = 0; // Single value config
  u32 *val;
  val = bpf_map_lookup_elem (&config, &index);
  if (pid == val)
    {
      key.user_stack_id = bpf_get_prandom_u32 (); // TODO(kakkoyun): Generate a
                                                  // random number.
      backtrace (&ctx->regs, &user_stack_traces);
    }
  else
    {
      int stack_id = bpf_get_stackid (ctx, &stack_traces, BPF_F_USER_STACK);
      if (stack_id >= 0)
        key.user_stack_id = stack_id;
      else
        key.user_stack_id = 0;
    }

  // get kernel stack
  key.kernel_stack_id = bpf_get_stackid (ctx, &stack_traces, 0);

  u64 zero = 0;
  u64 *count;
  count = bpf_map_lookup_or_try_init (&counts, &key, &zero);
  if (!count)
    return 0;

  __sync_fetch_and_add (count, 1);

  return 0;
}

char LICENSE[] SEC ("license") = "GPL";

void
backtrace (bpf_user_pt_regs_t *regs, u64 *stack)
{
  long unsigned int *rip = regs->ip;
  long unsigned int *rsp = regs->sp;
  int d;
  for (d = 0; d < MAX_STACK_DEPTH; d++)
    {
      stack[d] = *rip;
      if (*rip == 0)
        break;

      int i = binary_search (rip);
      if (i >= 0)
        break;

      //     let ins = if let Some(ins) = RSP.get(i) {
      //         ins
      //     } else {
      //         break;
      //     };
      void *ins;
      ins = bpf_map_lookup_elem (&rsps, &i);
      if (ins == NULL)
        break;

      //     let cfa = if let Some(cfa) = execute_instruction(&ins, rip, rsp,
      //     0)
      //     {
      //         cfa
      //     } else {
      //         break;
      //     };
      u64 cfa;
      cfa = execute_instruction ((stack_unwind_instruction_t *)ins, rip, rsp,
                                 0);
      if (cfa == NULL)
        break;

      //     let ins = if let Some(ins) = RIP.get(i) {
      //         ins
      //     } else {
      //         break;
      //     };
      ins = bpf_map_lookup_elem (&rips, &i);
      if (ins == NULL)
        break;

      //     rip = execute_instruction(&ins, rip, rsp,
      //     cfa).unwrap_or_default(); rsp = cfa;
      rip = execute_instruction ((stack_unwind_instruction_t *)ins, rip, rsp,
                                 cfa);
      if (rip == NULL)
        // rip = default; // TODO(kakkoyun): Fix this.
        rip = 0;
      rsp = cfa;
    }
  return;
}

u32
binary_search (u64 rip)
{
  int left = 0;
  // int right = CONFIG.get (0).unwrap_or (1) - 1;
  int right = 0xffffffff; // TODO(kakkoyun): Fix this.
  u32 mid = 0;
  int i = 0;
  // while (left <= right)
  //   {
  //     mid = (left + right) / 2;
  //     if (rip < CONFIG.get(mid).unwrap_or(0))
  //       right = mid - 1;
  //     else
  //       left = mid + 1;
  //   }
  for (i = 0; i < MAX_BINARY_SEARCH_DEPTH; i++)
    {
      if (left > right)
        break;

      mid = (left + right) / 2;

      // u64 pc = PC.get(i).unwrap_or(u64::MAX);
      u64 pc = ULONG_MAX;
      pc = bpf_map_lookup_elem (&pcs, &i);
      if (pc == NULL)
        pc = ULONG_MAX;

      if (pc < rip)
        left = mid;
      else
        right = mid;
    }
  return mid;
}

u64 *
execute_instruction (stack_unwind_instruction_t *ins, u64 rip, u64 rsp,
                     u64 cfa)
{
  //     match ins.op {
  //         1 => {
  //             let unsafe_ptr = (cfa as i64 + ins.offset as i64) as *const
  //             core::ffi::c_void; let mut res: u64 = 0; if unsafe {
  //             sys::bpf_probe_read(&mut res as *mut _ as *mut _, 8,
  //             unsafe_ptr) } == 0 {
  //                 Some(res)
  //             } else {
  //                 None
  //             }
  //         }
  //         2 => Some((rip as i64 + ins.offset as i64) as u64),
  //         3 => Some((rsp as i64 + ins.offset as i64) as u64),
  //         _ => None,
  //     }
  u64 addr;
  if (ins->op == 1)
    {
      u64 unsafe_ptr = cfa + ins->offset;

      int res;
      res = bpf_probe_read (&addr, 8, &unsafe_ptr);
      if (res != 0)
        return NULL;
    }
  else if (ins->op == 2)
    addr = rip + ins->offset;
  else if (ins->op == 3)
    addr = rsp + ins->offset;
  else
    return NULL;

  return &addr;
}
