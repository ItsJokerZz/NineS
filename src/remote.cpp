#include "remote.hpp"
#include "nineS.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#ifdef __PROSPERO__
#include <ps5/kernel.h>
#endif

extern "C" {
extern const unsigned char remote_stager[], remote_stager_end[];
}

__asm__(".pushsection .text.remote_stager,\"ax\",@progbits\n"
        ".global remote_stager, remote_stager_end\n"
        "remote_stager:\n"
        "push %rbx\n mov %rdi,%rbx\n"
        "mov 592(%rbx),%rax\n test %rax,%rax\n jz 1f\n"
        "xor %edi,%edi\n xor %esi,%esi\n call *%rax\n"
        "cltq\n mov %rax,600(%rbx)\n movl $1,608(%rbx)\n"
        "1:\n mov (%rbx),%rax\n"
        "mov 8(%rbx),%rdi\n mov 16(%rbx),%rsi\n mov 24(%rbx),%rdx\n"
        "mov 32(%rbx),%rcx\n mov 40(%rbx),%r8\n mov 48(%rbx),%r9\n"
        "call *%rax\n mov %rax,56(%rbx)\n movl $1,64(%rbx)\n"
        "xor %eax,%eax\n pop %rbx\n ret\n"
        "remote_stager_end:\n .popsection\n");

struct RemoteCall {
  uint64_t function, args[6];
  int64_t result;
  uint32_t done, reserved;
  uint64_t thread;
  char path[remote_path_max];
  uint64_t first;
  int64_t first_result;
  uint32_t first_done, padding;
  uint64_t attr;
};

static_assert(offsetof(RemoteCall, function) == 0 &&
              offsetof(RemoteCall, args) == 8 &&
              offsetof(RemoteCall, result) == 56 &&
              offsetof(RemoteCall, done) == 64 &&
              offsetof(RemoteCall, first) == 592 &&
              offsetof(RemoteCall, first_result) == 600 &&
              offsetof(RemoteCall, first_done) == 608);

static constexpr size_t data_offset = 0x4000;
static constexpr size_t staging_size = 0x8000;
static constexpr unsigned poll_ms = 100;

static_assert(data_offset + sizeof(RemoteCall) <= staging_size);

enum class Spawn { Failed, Started, Unknown };

uint64_t monotonic_ms() {
  timespec now{};

  clock_gettime(CLOCK_MONOTONIC, &now);

  return static_cast<uint64_t>(now.tv_sec) * 1000 + now.tv_nsec / 1000000;
}

static bool call_ok(pid_t pid, intptr_t function, const uint64_t args[6]) {
  intptr_t result = -1;

  return function && !pt_call(pid, function, args, &result) &&
         static_cast<int>(result) == 0;
}

static bool size_stack(pid_t pid, uint64_t attr, size_t stack) {
  const uint64_t init[6] = {attr};
  const uint64_t resize[6] = {attr, stack};

  if (!call_ok(pid, pt_resolve(pid, "pthread_attr_init"), init))
    return false;

  if (call_ok(pid, pt_resolve(pid, "pthread_attr_setstacksize"), resize))
    return true;

  call_ok(pid, pt_resolve(pid, "pthread_attr_destroy"), init);

  return false;
}

static Spawn create_worker(pid_t pid, intptr_t create, uintptr_t staging,
                           uint64_t attr) {
  const uint64_t data = staging + data_offset;
  const uint64_t args[6] = {data + offsetof(RemoteCall, thread), attr, staging,
                            data};
  intptr_t created = -1;

  if (pt_call(pid, create, args, &created))
    return Spawn::Unknown;

  return static_cast<int>(created) == 0 ? Spawn::Started : Spawn::Failed;
}

static Spawn spawn_worker(pid_t pid, uintptr_t staging, size_t stack) {
  const intptr_t create = pt_resolve(pid, "pthread_create");

  if (!create)
    return Spawn::Failed;

  const uint64_t attr = staging + data_offset + offsetof(RemoteCall, attr);

  if (!stack || !size_stack(pid, attr, stack))
    return create_worker(pid, create, staging, 0);

  Spawn spawned = create_worker(pid, create, staging, attr);
  const uint64_t release[6] = {attr};

  call_ok(pid, pt_resolve(pid, "pthread_attr_destroy"), release);

  return spawned == Spawn::Failed ? create_worker(pid, create, staging, 0)
                                  : spawned;
}

static bool join_worker(pid_t pid, uint64_t thread) {
  const intptr_t join = pt_resolve(pid, "pthread_join");
  const uint64_t args[6] = {thread};
  intptr_t joined = -1;

  return join && !pt_call(pid, join, args, &joined) &&
         static_cast<int>(joined) == 0;
}

static bool write_staging(pid_t pid, uintptr_t staging,
                          const RemoteCall &call) {
  const size_t code_size = remote_stager_end - remote_stager;

  return code_size < data_offset &&
         !pt_copyin(pid, remote_stager, staging, code_size) &&
         !pt_copyin(pid, &call, staging + data_offset, sizeof(call));
}

intptr_t map_executable(pid_t pid, size_t size) {
#ifdef __PROSPERO__
  const intptr_t mapped = pt_mmap(pid, 0, size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  if (mapped <= 0)
    return 0;

  if (kernel_mprotect(pid, mapped, size, PROT_READ | PROT_WRITE | PROT_EXEC)) {
    pt_munmap(pid, mapped, size);

    return 0;
  }

  return mapped;
#else
  return pt_mmap(pid, 0, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
}

static uintptr_t start_remote_call(pid_t pid, uintptr_t function,
                                   const uint64_t args[6], const char *path,
                                   uintptr_t before, size_t stack = 0) {
  if (pid <= 0 || !function || (path && strlen(path) >= remote_path_max))
    return 0;

  Attachment target(pid);

  if (!target.held)
    return 0;

  const intptr_t mapped = map_executable(pid, staging_size);

  if (mapped <= 0)
    return 0;

  const uintptr_t staging = mapped;
  RemoteCall call{};

  call.function = function;
  call.first = before;
  memcpy(call.args, args, sizeof(call.args));

  if (path) {
    strcpy(call.path, path);
    call.args[0] = staging + data_offset + offsetof(RemoteCall, path);
  }

  if (!write_staging(pid, staging, call) ||
      spawn_worker(pid, staging, stack) == Spawn::Failed) {
    pt_munmap(pid, staging, staging_size);
    return 0;
  }

  return staging;
}

static int finish_remote_call(pid_t pid, uintptr_t staging, int64_t &result,
                              RemoteBefore *before) {
  Attachment target(pid);

  if (!target.held)
    return -1;

  RemoteCall call{};

  if (pt_copyout(pid, staging + data_offset, &call, sizeof(call)))
    return -1;

  if (!call.done)
    return 0;

  if (!join_worker(pid, call.thread))
    return -1;

  result = call.result;

  if (before)
    *before = {call.first_done != 0, call.first_result};

  pt_munmap(pid, staging, staging_size);

  return 1;
}

RemoteState remote_call(pid_t pid, uintptr_t function, const uint64_t args[6],
                        const char *path, uintptr_t before, unsigned timeout_ms,
                        int64_t &result, RemoteBefore *ran) {
  const uintptr_t staging =
      start_remote_call(pid, function, args, path, before);

  if (!staging)
    return RemoteState::Failed;

  const uint64_t deadline = monotonic_ms() + timeout_ms;

  for (;;) {
    const int finished = finish_remote_call(pid, staging, result, ran);

    if (finished)
      return finished > 0 ? RemoteState::Done : RemoteState::Failed;

    if (monotonic_ms() >= deadline)
      return RemoteState::TimedOut;

    usleep(poll_ms * 1000);
  }
}

bool remote_spawn(pid_t pid, uintptr_t function, const uint64_t args[6],
                  size_t stack) {
  return start_remote_call(pid, function, args, nullptr, 0, stack) != 0;
}
