#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

extern "C" {
#include "ptrace.h"
}

constexpr size_t remote_path_max = 512;

struct Attachment {
  pid_t pid;
  bool held;

  explicit Attachment(pid_t target) : pid(target), held(!pt_attach(target)) {}

  ~Attachment() {
    if (held)
      pt_detach(pid, 0);
  }

  Attachment(const Attachment &) = delete;
  Attachment &operator=(const Attachment &) = delete;
};

struct RemoteBefore {
  bool ran;
  int64_t result;
};

enum class RemoteState { Done, Failed, TimedOut };

inline const char *file_name(const char *path) {
  const char *name = path;

  for (const char *at = path; *at; ++at)
    if (*at == '/')
      name = at + 1;

  return name;
}

uint64_t monotonic_ms();

intptr_t map_executable(pid_t pid, size_t size);

void log_line(const char *format, ...) __attribute__((format(printf, 1, 2)));

RemoteState remote_call(pid_t pid, uintptr_t function, const uint64_t args[6],
                        const char *path, uintptr_t before, unsigned timeout_ms,
                        int64_t &result, RemoteBefore *ran = nullptr);

bool remote_spawn(pid_t pid, uintptr_t function, const uint64_t args[6],
                  size_t stack = 0);
