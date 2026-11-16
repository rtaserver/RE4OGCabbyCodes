#include "crash.h"

#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "log.h"
#include "mem.h"

namespace re4cc {
namespace {

LPTOP_LEVEL_EXCEPTION_FILTER g_previous = nullptr;  // the filter ours passes an exception on to
using SetFilterFn = LPTOP_LEVEL_EXCEPTION_FILTER(WINAPI*)(LPTOP_LEVEL_EXCEPTION_FILTER);
SetFilterFn g_orig_set_filter = nullptr;
bool g_inert_said = false;                           // SetUnhandledExceptionFilter made to do nothing: logged
bool g_replacer_logged = false;                      // a filter found over ours has been logged,
LPTOP_LEVEL_EXCEPTION_FILTER g_replacer_said = nullptr;  // and the last one was this

// An exception as the filter tells one from another.
struct Seen {
  DWORD code = 0;
  void* at = nullptr;
  DWORD thread = 0;
  DWORD esp = 0;
};
bool same(const Seen& a, const Seen& b) {
  return a.code == b.code && a.at == b.at && a.thread == b.thread && a.esp == b.esp;
}

// The exception written out last: the same one given to ours again gets a line,
// not a second dump.
Seen g_last;
unsigned g_again = 0;

// The threads in on_exception now, each with the exceptions ours is passing on
// there, outermost first. Ours given one of those again from further down its
// own call is a loop (on_exception). A new one is an exception raised while the
// filter ours passed the last one on to ran - a packer's handler may raise one
// on purpose - and is passed on as any other, but not past kMaxDepth.
constexpr int kInsideSlots = 8;
constexpr int kMaxDepth = 3;
struct Inside {
  volatile LONG thread;  // 0: free; only its thread touches the rest
  int depth;
  Seen seen[kMaxDepth];
};
Inside g_inside[kInsideSlots] = {};

const char* code_name(DWORD code) {
  switch (code) {
    case EXCEPTION_ACCESS_VIOLATION: return "ACCESS_VIOLATION";
    case EXCEPTION_ILLEGAL_INSTRUCTION: return "ILLEGAL_INSTRUCTION";
    case EXCEPTION_STACK_OVERFLOW: return "STACK_OVERFLOW";
    case EXCEPTION_INT_DIVIDE_BY_ZERO: return "INT_DIVIDE_BY_ZERO";
    case EXCEPTION_PRIV_INSTRUCTION: return "PRIV_INSTRUCTION";
    case EXCEPTION_IN_PAGE_ERROR: return "IN_PAGE_ERROR";
    default: return "exception";
  }
}

void describe(const void* addr, char* out, size_t n) {
  HMODULE owner = nullptr;
  char path[MAX_PATH] = "?";
  if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                             GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                         static_cast<LPCSTR>(addr), &owner) &&
      owner) {
    GetModuleFileNameA(owner, path, MAX_PATH);
    const char* leaf = std::strrchr(path, '\\');
    std::snprintf(out, n, "%s+0x%X", leaf ? leaf + 1 : path,
                  static_cast<unsigned>(reinterpret_cast<uintptr_t>(addr) -
                                        reinterpret_cast<uintptr_t>(owner)));
  } else {
    std::snprintf(out, n, "%p (no module)", addr);
  }
}

void describe_filter(LPTOP_LEVEL_EXCEPTION_FILTER f, char* out, size_t n) {
  if (f) describe(reinterpret_cast<const void*>(f), out, n);
  else std::snprintf(out, n, "none");
}

// Code that can be called: what ours chains to must be. A value that only
// claims to be the previous filter (below) is not.
bool is_code(LPTOP_LEVEL_EXCEPTION_FILTER f) {
  MEMORY_BASIC_INFORMATION mbi{};
  if (!f || !VirtualQuery(reinterpret_cast<const void*>(f), &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return false;
  if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
  return (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
}

// The first instruction a call of `fn` runs, past the jumps in front of it
// (kernel32's export jumps into kernelbase's on newer Windows; a hook's patch is
// a jump too). Null when it cannot be read.
const uint8_t* first_code(const void* fn) {
  auto p = static_cast<const uint8_t*>(fn);
  for (int hop = 0; hop < 4; ++hop) {
    if (!mem::readable(p, 6)) return nullptr;
    if (p[0] == 0xFF && p[1] == 0x25) {  // jmp [slot]
      uintptr_t slot = 0, to = 0;
      std::memcpy(&slot, p + 2, sizeof(slot));
      if (!mem::read_safe(slot, &to)) return nullptr;
      p = reinterpret_cast<const uint8_t*>(to);
    } else if (p[0] == 0xE9) {  // jmp rel32
      int32_t rel = 0;
      std::memcpy(&rel, p + 1, sizeof(rel));
      p += 5 + rel;
    } else if (p[0] == 0xEB) {  // jmp rel8
      p += 2 + static_cast<int8_t>(p[1]);
    } else {
      return p;
    }
  }
  return mem::readable(p, 6) ? p : nullptr;
}

// Some crash handlers keep the slot for themselves: they set their filter, then
// write a `ret 4` over SetUnhandledExceptionFilter's first bytes so that nobody
// can set another (re4_tweaks does when a CrashDumps folder is beside bio4.exe).
// A call then changes nothing and "returns" whatever eax held - no filter at
// all, which ours must neither take for the previous one nor chain to. Their
// handler reports the crash; this log does not see it.
bool slot_taken() {
  const uint8_t* p = first_code(reinterpret_cast<const void*>(g_orig_set_filter));
  if (!p) return false;
  const auto is_ret = [](const uint8_t* q) { return q[0] == 0xC3 || (q[0] == 0xC2 && q[1] == 0x04 && q[2] == 0x00); };
  const bool inert = is_ret(p) || ((p[0] == 0x33 || p[0] == 0x31) && p[1] == 0xC0 && is_ret(p + 2));  // xor eax,eax first
  if (inert && !g_inert_said) {
    g_inert_said = true;
    char where[MAX_PATH + 32];
    describe(p, where, sizeof(where));
    logf("crash: SetUnhandledExceptionFilter has been made to do nothing (a ret at %s) - another crash handler keeps "
         "the slot for itself (re4_tweaks does when a CrashDumps folder is beside bio4.exe, and writes its crash "
         "reports there); a crash is its to report, not this log's",
         where);
  }
  return inert;
}

Seen identity(const EXCEPTION_POINTERS* info) {
  Seen s;
  s.thread = GetCurrentThreadId();
  if (info && info->ExceptionRecord) {
    s.code = info->ExceptionRecord->ExceptionCode;
    s.at = info->ExceptionRecord->ExceptionAddress;
  }
  if (info && info->ContextRecord) s.esp = info->ContextRecord->Esp;
  return s;
}

// One exception, as the filter sees it. True when it is the one written out
// last, given to ours again (it then gets a line, not a second dump).
bool write_out(EXCEPTION_POINTERS* info, const Seen& seen) {
  if (!info || !info->ExceptionRecord) {
    logf("CRASH: an exception without its record");
    return false;
  }
  const EXCEPTION_RECORD* rec = info->ExceptionRecord;
  const CONTEXT* ctx = info->ContextRecord;
  char where[MAX_PATH + 32];
  describe(rec->ExceptionAddress, where, sizeof(where));
  if (same(seen, g_last)) {
    logf("CRASH: the same %s at %s again (%u) - our filter was given it once more", code_name(seen.code), where,
         ++g_again);
    return true;
  }
  g_last = seen;
  g_again = 0;

  logf("CRASH: %s (0x%08lX) at %s (thread %lu)", code_name(rec->ExceptionCode), rec->ExceptionCode, where,
       GetCurrentThreadId());
  // For an access violation the record carries what was touched and how; a
  // null or freed address there is the difference between a bad pointer and
  // a bad instruction, and it is not in the register dump below.
  if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2) {
    const ULONG_PTR kind = rec->ExceptionInformation[0];
    logf("       %s address %08lX", kind == 1 ? "writing" : kind == 8 ? "executing" : "reading",
         static_cast<unsigned long>(rec->ExceptionInformation[1]));
  }
  if (!ctx) return false;
  logf("       eip=%08lX esp=%08lX ebp=%08lX eax=%08lX ebx=%08lX ecx=%08lX edx=%08lX esi=%08lX edi=%08lX", ctx->Eip,
       ctx->Esp, ctx->Ebp, ctx->Eax, ctx->Ebx, ctx->Ecx, ctx->Edx, ctx->Esi, ctx->Edi);
  // The top of the stack as it is: the faulting function's frame and its
  // callers' locals - in a game function, what it was working on (the values a
  // register dump does not hold any more).
  const auto* sp = reinterpret_cast<const uint32_t*>(static_cast<uintptr_t>(ctx->Esp));
  for (int row = 0; row < 6; ++row) {
    const uint32_t* r = sp + row * 8;
    if (!mem::readable(r, 8 * sizeof(uint32_t))) break;
    logf("       esp+%03X: %08X %08X %08X %08X %08X %08X %08X %08X", row * 32, r[0], r[1], r[2], r[3], r[4], r[5],
         r[6], r[7]);
  }
  // A few return addresses off the stack, for the ones that land in a module.
  auto* slots = reinterpret_cast<void* const*>(sp);
  for (int i = 0, shown = 0; i < 128 && shown < 8; ++i) {
    if (!mem::readable(slots + i, sizeof(void*))) break;
    void* v = slots[i];
    HMODULE owner = nullptr;
    if (v && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                    GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                static_cast<LPCSTR>(v), &owner) &&
        owner) {
      describe(v, where, sizeof(where));
      logf("       stack[%03d] %s", i, where);
      ++shown;
    }
  }
  return false;
}

// This thread's slot in g_inside (its depth 0 if new); null when none is free
// (it then goes unguarded).
Inside* inside_slot() {
  const LONG me = static_cast<LONG>(GetCurrentThreadId());
  for (Inside& s : g_inside)
    if (s.thread == me) return &s;
  for (Inside& s : g_inside)
    if (InterlockedCompareExchange(&s.thread, me, 0) == 0) {
      s.depth = 0;
      return &s;
    }
  return nullptr;
}

LONG WINAPI on_exception(EXCEPTION_POINTERS* info) {
  const Seen now = identity(info);
  Inside* in = inside_slot();
  const int depth = in ? in->depth : 0;
  if (depth > 0) {
    // Ours is already running on this thread, further up.
    char where[MAX_PATH + 32] = "?";
    if (now.at) describe(now.at, where, sizeof(where));
    for (int i = 0; i < depth; ++i) {
      if (!same(now, in->seen[i])) continue;
      // The filter it passed this exception on to has handed it back: it
      // chains to the filter it replaced, and that was ours (a filter set over
      // ours that reassert put ours back over). Passing it on again would go
      // round for ever.
      logf("       (back in our filter with the same exception from the one it passed it on to - %s at %s; not "
           "passed on again)",
           code_name(now.code), where);
      return EXCEPTION_CONTINUE_SEARCH;
    }
    if (depth >= kMaxDepth) {
      logf("       (%s at %s, raised while ours passes on %d others on this thread - not passed on)",
           code_name(now.code), where, depth);
      return EXCEPTION_CONTINUE_SEARCH;
    }
    logf("       (another exception, raised while the filter ours passed the last one on to ran:)");
  }
  if (in) {
    in->seen[depth] = now;
    in->depth = depth + 1;
  }
  const bool again = write_out(info, now);
  LONG r = EXCEPTION_CONTINUE_SEARCH;
  if (const LPTOP_LEVEL_EXCEPTION_FILTER next = g_previous) {
    if (!again) {
      char who[MAX_PATH + 32];
      describe_filter(next, who, sizeof(who));
      logf("       passed on to the filter at %s", who);
    }
    // A filter we chain to can handle an exception raised on purpose; that is
    // no crash, and the log should say so.
    r = next(info);
    if (r == EXCEPTION_CONTINUE_EXECUTION)
      logf("       (the filter we chain to handled it and the program went on - not a crash)");
  }
  if (in) {
    in->depth = depth;
    if (depth == 0) InterlockedExchange(&in->thread, 0);
  }
  return r;
}

// SetUnhandledExceptionFilter has one global slot, and the game's CRT takes it
// during start-up, after our DllMain has run - and a CRT's fatal-error path
// sets it to null on purpose before calling UnhandledExceptionFilter, so that
// nothing intercepts the report. Either way ours would never run and a crash
// would leave no line in the log. bio4.exe's import of it is re-pointed at
// this hook from DllMain, before the CRT starts, and reassert_crash_filter()
// covers every path we do not see.
LPTOP_LEVEL_EXCEPTION_FILTER WINAPI hk_set_filter(LPTOP_LEVEL_EXCEPTION_FILTER next) {
  LPTOP_LEVEL_EXCEPTION_FILTER previous = g_previous;
  g_previous = next;
  char who[MAX_PATH + 32];
  describe_filter(next, who, sizeof(who));
  if (slot_taken()) {
    logf("crash: the game set its top-level exception filter (%s) - it did not go in: the slot is another crash "
         "handler's",
         who);
    return previous;
  }
  if (g_orig_set_filter) g_orig_set_filter(&on_exception);
  logf("crash: the game set its top-level exception filter (%s); ours stays on top, chaining to it", who);
  return previous;
}

}  // namespace

void describe_address(void* addr, char* out, unsigned n) { describe(addr, out, n); }

void install_crash_logger() {
  g_orig_set_filter = &SetUnhandledExceptionFilter;
  if (slot_taken()) return;
  const LPTOP_LEVEL_EXCEPTION_FILTER previous = SetUnhandledExceptionFilter(&on_exception);
  g_previous = is_code(previous) ? previous : nullptr;
  logf("crash logger installed (the game's own filter is chained once it sets one)");
}

void* crash_filter_hook() { return reinterpret_cast<void*>(&hk_set_filter); }

void reassert_crash_filter() {
  if (slot_taken()) return;
  const LPTOP_LEVEL_EXCEPTION_FILTER cur = SetUnhandledExceptionFilter(&on_exception);
  if (cur == &on_exception) return;
  // Another filter went over ours without the game's import. Ours goes back on
  // top and passes exceptions on to it - unless it is no code at all. A filter
  // that chains to the one it replaced comes back to ours (on_exception stops
  // it there). One that keeps putting itself back is logged once.
  const bool code = is_code(cur);
  if (code) g_previous = cur;
  if (g_replacer_logged && cur == g_replacer_said) return;
  g_replacer_logged = true;
  g_replacer_said = cur;
  char who[MAX_PATH + 32];
  describe_filter(cur, who, sizeof(who));
  if (cur && !code)
    logf("crash: the top-level filter had been replaced by %s, which is no code - ours is back on top, not chaining to "
         "it",
         who);
  else
    logf("crash: the top-level filter had been replaced (%s) - ours is back on top%s", who,
         cur ? ", chaining to it" : "");
}

}  // namespace re4cc
