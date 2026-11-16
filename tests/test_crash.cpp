// The crash logger (src/crash.cpp) outside the game, under Wine:
//
//   i686-w64-mingw32-g++ -std=c++20 -O2 -Wall -DWIN32_LEAN_AND_MEAN -DNOMINMAX -static -Isrc tests/test_crash.cpp
//       src/crash.cpp -o tests/build/test_crash.exe
//   wine tests/build/test_crash.exe                                               # "PASSED"
//
// The filter is called as UnhandledExceptionFilter calls the top-level one, with
// a made-up access violation (the game's crash of 2026-11-10: memcpy from a null
// source, esi 0). In turn: the game's own filter set through its import (the
// hook) and chained to; the same exception given to ours again (a line, not a
// second dump, still chained); a filter set over ours that chains to the one it
// replaced - ours - which reassert puts ours back over and chains to (ours must
// stop there, not go round); a "previous filter" that is no code (not chained
// to); a crash on another thread while one is inside the chain (its own dump);
// and SetUnhandledExceptionFilter made to do nothing with a `ret 4` over its
// first bytes, as re4_tweaks does with a CrashDumps folder (said once, nothing
// taken for a filter, no line a second). Each is checked in the log lines.
#include <windows.h>

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "crash.h"
#include "log.h"

namespace {

std::vector<std::string> g_lines;
CRITICAL_SECTION g_lock;
int g_failures = 0;

void check(bool ok, const char* what) {
  std::printf("%s %s\n", ok ? "  ok  " : "  FAIL", what);
  if (!ok) ++g_failures;
}

size_t count(const char* needle, size_t from = 0) {
  size_t n = 0;
  EnterCriticalSection(&g_lock);
  for (size_t i = from; i < g_lines.size(); ++i)
    if (g_lines[i].find(needle) != std::string::npos) ++n;
  LeaveCriticalSection(&g_lock);
  return n;
}

size_t mark() {
  EnterCriticalSection(&g_lock);
  const size_t n = g_lines.size();
  LeaveCriticalSection(&g_lock);
  return n;
}

using Filter = LPTOP_LEVEL_EXCEPTION_FILTER;
using SetFilterFn = Filter(WINAPI*)(Filter);

// The filter on top now, the slot left as it was.
Filter top() {
  const Filter t = SetUnhandledExceptionFilter(nullptr);
  SetUnhandledExceptionFilter(t);
  return t;
}

// A made-up access violation: reading address 0 at `at`, with a stack of its own.
struct Fake {
  EXCEPTION_RECORD rec;
  CONTEXT ctx;
  EXCEPTION_POINTERS ptrs;
  uint32_t stack[160];
};
void make(Fake* f, void* at, uint32_t edi) {
  std::memset(f, 0, sizeof(*f));
  f->rec.ExceptionCode = EXCEPTION_ACCESS_VIOLATION;
  f->rec.ExceptionAddress = at;
  f->rec.NumberParameters = 2;
  for (int i = 0; i < 160; ++i) f->stack[i] = 0x01000000u + i;
  f->stack[3] = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&make));  // a return address in this exe
  f->ctx.ContextFlags = CONTEXT_FULL;
  f->ctx.Eip = static_cast<DWORD>(reinterpret_cast<uintptr_t>(at));
  f->ctx.Esp = static_cast<DWORD>(reinterpret_cast<uintptr_t>(f->stack));
  f->ctx.Eax = 0x10;
  f->ctx.Ecx = 4;
  f->ctx.Esi = 0;
  f->ctx.Edi = edi;
  f->ptrs.ExceptionRecord = &f->rec;
  f->ptrs.ContextRecord = &f->ctx;
}

// The game's own filter (bio4.exe's CRT's: nothing for a non-C++ exception).
int g_game_calls = 0;
LONG WINAPI game_filter(EXCEPTION_POINTERS*) {
  ++g_game_calls;
  return EXCEPTION_CONTINUE_SEARCH;
}

// A filter set over ours with the real API, that passes every exception on to
// the one it replaced (as many crash loggers do).
Filter g_x_prev = nullptr;
int g_x_calls = 0;
LONG WINAPI x_filter(EXCEPTION_POINTERS* p) {
  ++g_x_calls;
  return g_x_prev ? g_x_prev(p) : EXCEPTION_CONTINUE_SEARCH;
}

// For the two threads: the first, inside x_filter, waits for the second's crash.
HANDLE g_inside_x = nullptr, g_second_done = nullptr;
DWORD g_waiting_thread = 0;
LONG WINAPI x_waiting_filter(EXCEPTION_POINTERS* p) {
  ++g_x_calls;
  if (GetCurrentThreadId() == g_waiting_thread) {
    SetEvent(g_inside_x);
    WaitForSingleObject(g_second_done, 5000);
  }
  return g_x_prev ? g_x_prev(p) : EXCEPTION_CONTINUE_SEARCH;
}

// A filter that raises a new exception of its own while it handles one - a
// packer's handler may, on purpose - which reaches the top-level filter (ours),
// and handles that one itself (goes on); the first it lets go.
Filter g_top = nullptr;
Fake g_nested;
int g_y_calls = 0;
LONG g_y_nested_r = -9;
LONG WINAPI y_filter(EXCEPTION_POINTERS* p) {
  if (++g_y_calls == 1) {
    g_y_nested_r = g_top(&g_nested.ptrs);
    return EXCEPTION_CONTINUE_SEARCH;
  }
  return p == &g_nested.ptrs ? EXCEPTION_CONTINUE_EXECUTION : EXCEPTION_CONTINUE_SEARCH;
}

// A filter that raises a new exception every time it runs (one that crashes in
// itself, again and again).
Fake g_runaway[8];
int g_z_calls = 0;
LONG WINAPI z_filter(EXCEPTION_POINTERS*) {
  const int k = g_z_calls++;
  return k < 8 ? g_top(&g_runaway[k].ptrs) : EXCEPTION_CONTINUE_SEARCH;
}

struct Fire {
  Filter f;
  Fake* fake;
  LONG r;
};
DWORD WINAPI fire_thread(void* arg) {
  auto* a = static_cast<Fire*>(arg);
  a->r = a->f(&a->fake->ptrs);
  return 0;
}

}  // namespace

namespace re4cc {
void log_init(const char*) {}
void log_shutdown() {}
void logf(const char* fmt, ...) {
  char buf[1024];
  va_list ap;
  va_start(ap, fmt);
  std::vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);
  EnterCriticalSection(&g_lock);
  g_lines.push_back(buf);
  std::printf("    | %s\n", buf);
  LeaveCriticalSection(&g_lock);
}
}  // namespace re4cc

int main() {
  InitializeCriticalSection(&g_lock);
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  using namespace re4cc;

  std::printf("install, and the game's filter set through its import:\n");
  install_crash_logger();
  const Filter ours = top();
  check(ours != nullptr && ours != &game_filter && ours != &x_filter, "ours is on top after install");
  const auto hook = reinterpret_cast<SetFilterFn>(crash_filter_hook());
  hook(&game_filter);
  check(top() == ours, "ours stays on top when the game sets its filter");

  std::printf("a crash:\n");
  Fake f1;
  make(&f1, reinterpret_cast<void*>(&top), 0x0C5D77C);
  size_t m = mark();
  LONG r = ours(&f1.ptrs);
  check(r == EXCEPTION_CONTINUE_SEARCH, "the search goes on");
  check(count("CRASH: ACCESS_VIOLATION", m) == 1, "one dump");
  check(count("reading address 00000000", m) == 1, "what was touched");
  check(count("esi=00000000 edi=00C5D77C", m) == 1, "every register, esi and edi among them");
  check(count("esp+000: 01000000 01000001 01000002", m) == 1 && count("esp+0A0:", m) == 1,
        "the top of the stack, raw (six rows)");
  check(count("stack[003] test_crash.exe+", m) == 1, "a return address named by its module");
  check(count("passed on to the filter at test_crash.exe+", m) == 1, "the filter it chains to, named");
  check(g_game_calls == 1, "the game's filter ran once");

  std::printf("the same exception again:\n");
  m = mark();
  ours(&f1.ptrs);
  check(count("CRASH: the same ACCESS_VIOLATION", m) == 1 && count("eip=", m) == 0, "a line, not a second dump");
  check(g_game_calls == 2, "still chained");

  std::printf("a filter set over ours that chains to the one it replaced:\n");
  g_x_prev = SetUnhandledExceptionFilter(&x_filter);
  check(g_x_prev == ours, "it saved ours as the one to chain to");
  m = mark();
  reassert_crash_filter();
  check(top() == ours, "reassert puts ours back on top");
  check(count("replaced (test_crash.exe+", m) == 1 && count("chaining to it", m) == 1, "and says over whose");
  Fake f2;
  make(&f2, reinterpret_cast<void*>(&mark), 0x12345678);
  m = mark();
  r = ours(&f2.ptrs);
  check(g_x_calls == 1, "the other filter ran once - no loop");
  check(count("back in our filter", m) == 1, "the way back into ours is logged");
  check(count("CRASH: ACCESS_VIOLATION", m) == 1, "one dump for it");
  check(r == EXCEPTION_CONTINUE_SEARCH, "the search goes on");
  m = mark();
  SetUnhandledExceptionFilter(&x_filter);
  reassert_crash_filter();
  check(count("replaced", m) == 0, "a filter that puts itself back again is not logged again");

  std::printf("a previous filter that is no code:\n");
  SetUnhandledExceptionFilter(reinterpret_cast<Filter>(static_cast<uintptr_t>(0x3EA)));
  m = mark();
  reassert_crash_filter();
  check(top() == ours, "ours is back on top");
  check(count("which is no code", m) == 1, "said so");
  Fake f3;
  make(&f3, reinterpret_cast<void*>(&count), 1);
  const int x_before = g_x_calls;
  r = ours(&f3.ptrs);  // would jump to 0x3EA if it were chained to
  check(g_x_calls == x_before + 1, "still chained to the last filter that is code");

  std::printf("two threads:\n");
  g_x_prev = SetUnhandledExceptionFilter(&x_waiting_filter);
  reassert_crash_filter();
  g_inside_x = CreateEventA(nullptr, TRUE, FALSE, nullptr);
  g_second_done = CreateEventA(nullptr, TRUE, FALSE, nullptr);
  Fake fa, fb;
  make(&fa, reinterpret_cast<void*>(&fire_thread), 0xAAAA);
  make(&fb, reinterpret_cast<void*>(&x_waiting_filter), 0xBBBB);
  Fire a{ours, &fa, -9}, b{ours, &fb, -9};
  m = mark();
  HANDLE ta = CreateThread(nullptr, 0, fire_thread, &a, CREATE_SUSPENDED, &g_waiting_thread);
  ResumeThread(ta);
  check(WaitForSingleObject(g_inside_x, 5000) == WAIT_OBJECT_0, "the first thread is inside the chain");
  HANDLE tb = CreateThread(nullptr, 0, fire_thread, &b, 0, nullptr);
  WaitForSingleObject(tb, 5000);
  check(count("edi=0000BBBB", m) == 1, "the second thread's crash gets its own dump");
  SetEvent(g_second_done);
  WaitForSingleObject(ta, 5000);
  check(count("edi=0000AAAA", m) == 1, "and the first's has its own");
  check(count("back in our filter", m) == 2, "each stopped on its own thread");
  check(a.r == EXCEPTION_CONTINUE_SEARCH && b.r == EXCEPTION_CONTINUE_SEARCH, "both searches go on");
  CloseHandle(ta);
  CloseHandle(tb);

  std::printf("a new exception raised inside the filter ours passed one on to:\n");
  g_top = ours;
  SetUnhandledExceptionFilter(&y_filter);
  reassert_crash_filter();
  Fake f4;
  make(&f4, reinterpret_cast<void*>(&y_filter), 0x4444);
  make(&g_nested, reinterpret_cast<void*>(&z_filter), 0x5555);
  m = mark();
  r = ours(&f4.ptrs);
  check(g_y_calls == 2, "the new one is passed on as well (the filter ran for both)");
  check(g_y_nested_r == EXCEPTION_CONTINUE_EXECUTION, "and its answer for it comes back (it handled it)");
  check(count("another exception, raised while", m) == 1, "said so");
  check(count("edi=00004444", m) == 1 && count("edi=00005555", m) == 1, "each with its dump");
  check(count("handled it and the program went on", m) == 1, "the nested one went on - no crash");
  check(r == EXCEPTION_CONTINUE_SEARCH, "the first one's search goes on");

  std::printf("a filter that raises a new exception every time it runs:\n");
  SetUnhandledExceptionFilter(&z_filter);
  reassert_crash_filter();
  for (int k = 0; k < 8; ++k) make(&g_runaway[k], reinterpret_cast<char*>(&z_filter) + 1 + k, 0x7000 + k);
  Fake f5;
  make(&f5, reinterpret_cast<void*>(&y_filter), 0x6666);
  m = mark();
  r = ours(&f5.ptrs);
  check(g_z_calls == 3, "stopped three deep");
  check(count("others on this thread - not passed on", m) == 1, "said so");
  check(r == EXCEPTION_CONTINUE_SEARCH, "the search goes on");

  std::printf("SetUnhandledExceptionFilter made to do nothing (ret 4 over its first bytes):\n");
  auto* api = reinterpret_cast<uint8_t*>(&SetUnhandledExceptionFilter);
  uint8_t saved[3];
  std::memcpy(saved, api, 3);
  DWORD old = 0;
  VirtualProtect(api, 3, PAGE_EXECUTE_READWRITE, &old);
  const uint8_t ret4[3] = {0xC2, 0x04, 0x00};
  std::memcpy(api, ret4, 3);
  FlushInstructionCache(GetCurrentProcess(), api, 3);
  m = mark();
  for (int i = 0; i < 5; ++i) reassert_crash_filter();  // five seconds of ticks
  check(count("made to do nothing", m) == 1, "said once");
  check(count("replaced", m) == 0, "no garbage taken for a filter, no line a second");
  hook(&game_filter);
  check(count("it did not go in", m) == 1 && count("ours stays on top", m) == 0,
        "the game's call is not claimed to leave ours on top");
  install_crash_logger();
  check(count("crash logger installed", m) == 0, "install stands aside too");
  std::memcpy(api, saved, 3);
  VirtualProtect(api, 3, old, &old);
  FlushInstructionCache(GetCurrentProcess(), api, 3);
  check(top() == ours, "the API back as it was, ours is still on top");

  std::printf(g_failures ? "FAILED (%d)\n" : "PASSED\n", g_failures);
  return g_failures ? 1 : 0;
}
