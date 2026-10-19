#include "nineS.hpp"
#include "remote.hpp"

#include <cstdint>
#include <cstring>
#include <sys/types.h>
#include <sys/user.h>

#ifdef __ORBIS__
#include <ps4/kernel.h>
#endif

#ifdef __PROSPERO__
#include <ps5/kernel.h>
#endif

#include "ptrace.h"

static uint32_t module_handle(pid_t pid, const char *path) {
  uint32_t handle = 0;

  if (kernel_dynlib_handle(pid, file_name(path), &handle))
    return 0;

  return handle;
}

static bool usable(pid_t pid, const char *path) {
  return pid > 0 && path && *path && strlen(path) < remote_path_max;
}

static PluginFailure failure_of(RemoteState state) {
  return state == RemoteState::TimedOut ? PluginFailure::TimedOut
                                        : PluginFailure::NoThread;
}

static unsigned remaining(uint64_t deadline) {
  const uint64_t now = monotonic_ms();

  return now >= deadline ? 0 : static_cast<unsigned>(deadline - now);
}

bool plugin_loaded(pid_t pid, const char *path) {
  return usable(pid, path) && module_handle(pid, path) != 0;
}

PluginCall load_plugin(pid_t pid, const char *path, unsigned timeout_ms) {
  PluginCall call{};

  if (!usable(pid, path)) {
    call.failure = PluginFailure::BadPath;
    return call;
  }

  if (module_handle(pid, path)) {
    call.done = true;
    return call;
  }

  const uint64_t deadline = monotonic_ms() + timeout_ms;
  const intptr_t loader = pt_resolve(pid, "sceKernelLoadStartModule");

  if (!loader) {
    call.failure = PluginFailure::NoLoader;
    return call;
  }

  const uint64_t args[6]{};
  int64_t result = 0;
  RemoteState state =
      remote_call(pid, loader, args, path, 0, remaining(deadline), result);

  if (state != RemoteState::Done) {
    call.failure = failure_of(state);
    return call;
  }

  const int32_t handle = static_cast<int32_t>(result);

  if (handle <= 0) {
    call.result = handle;
    call.failure = PluginFailure::Rejected;
    return call;
  }

  call.done = true;

  const intptr_t entry =
      kernel_dynlib_dlsym(pid, static_cast<uint32_t>(handle), "plugin_load");

  if (entry <= 0)
    return call;

  state =
      remote_call(pid, entry, args, nullptr, 0, remaining(deadline), result);

  if (state != RemoteState::Done) {
    call.failure = failure_of(state);
    return call;
  }

  call.entered = true;
  call.result = static_cast<int32_t>(result);

  return call;
}

PluginCall unload_plugin(pid_t pid, const char *path, unsigned timeout_ms) {
  PluginCall call{};

  if (!usable(pid, path)) {
    call.failure = PluginFailure::BadPath;
    return call;
  }

  const uint32_t handle = module_handle(pid, path);

  if (!handle) {
    call.done = true;
    return call;
  }

  const intptr_t stop = pt_resolve(pid, "sceKernelStopUnloadModule");

  if (!stop) {
    call.failure = PluginFailure::NoLoader;
    return call;
  }

  const intptr_t entry = kernel_dynlib_dlsym(pid, handle, "plugin_unload");
  const uint64_t args[6] = {handle};
  int64_t result = 0;
  RemoteBefore before{};
  const RemoteState state = remote_call(
      pid, stop, args, nullptr, entry > 0 ? static_cast<uintptr_t>(entry) : 0,
      timeout_ms, result, &before);

  if (state != RemoteState::Done) {
    call.failure = failure_of(state);
    return call;
  }

  call.entered = before.ran;
  call.result = static_cast<int32_t>(before.result);
  call.done = static_cast<int32_t>(result) == 0;

  if (!call.done)
    call.failure = PluginFailure::Rejected;

  return call;
}
