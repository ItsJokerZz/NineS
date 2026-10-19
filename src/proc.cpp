#include "nineS.hpp"
#include "remote.hpp"

#include <cstdint>
#include <cstring>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <vector>

#ifdef __ORBIS__
#include <ps4/kernel.h>
#endif

#ifdef __PROSPERO__
#include <ps5/kernel.h>
#endif

static constexpr int zombie_state = 5;

static void copy_text(char *out, size_t size, const char *text, size_t limit) {
  size_t length = strnlen(text, limit);

  if (length >= size)
    length = size - 1;

  memcpy(out, text, length);
  out[length] = '\0';
}

static std::vector<ProcInfo> query_procs(int what, int arg) {
  int mib[] = {CTL_KERN, KERN_PROC, what, arg};
  size_t size = 0;

  if (sysctl(mib, 4, nullptr, &size, nullptr, 0))
    return {};

  std::vector<uint8_t> buffer(size + sizeof(kinfo_proc) * 16);

  size = buffer.size();

  if (sysctl(mib, 4, buffer.data(), &size, nullptr, 0))
    return {};

  std::vector<ProcInfo> list;

  for (size_t offset = 0; offset + sizeof(kinfo_proc) <= size;) {
    const auto *ki =
        reinterpret_cast<const kinfo_proc *>(buffer.data() + offset);
    const size_t record =
        ki->ki_structsize > 0 ? static_cast<size_t>(ki->ki_structsize) : 0;

    if (record < sizeof(kinfo_proc) || record > size - offset)
      break;

    if (ki->ki_stat != zombie_state) {
      ProcInfo info{};

      info.pid = ki->ki_pid;
      copy_text(info.name, sizeof(info.name), ki->ki_comm, sizeof(ki->ki_comm));
      copy_text(info.thread_name, sizeof(info.thread_name), ki->ki_tdname,
                sizeof(ki->ki_tdname));
      list.push_back(info);
    }

    offset += record;
  }

  return list;
}

std::vector<ProcInfo> list_procs() { return query_procs(KERN_PROC_PROC, 0); }

pid_t find_proc_by_name(const char *name) {
  if (!name || !*name)
    return -1;

  for (const ProcInfo &proc : query_procs(KERN_PROC_PROC, 0)) {
#ifdef __ORBIS__
    if (!strcmp(proc.name, name) || !strcmp(proc.thread_name, name))
#else
    if (!strcmp(proc.name, name))
#endif
      return proc.pid;
  }

  return -1;
}

bool get_proc_by_pid(pid_t pid, ProcInfo &info) {
  if (pid <= 0)
    return false;

  for (const ProcInfo &proc : query_procs(KERN_PROC_PID, pid)) {
    if (proc.pid == pid) {
      info = proc;
      return true;
    }
  }

  return false;
}

static constexpr uintptr_t main_module_base = 0x400000;

static void read_module(pid_t pid, uint32_t handle, ModuleInfo &info) {
  info.handle = handle;
  info.base = static_cast<uintptr_t>(kernel_dynlib_mapbase_addr(pid, handle));
  info.entry = static_cast<uintptr_t>(kernel_dynlib_entry_addr(pid, handle));
  info.init = static_cast<uintptr_t>(kernel_dynlib_init_addr(pid, handle));
  info.fini = static_cast<uintptr_t>(kernel_dynlib_fini_addr(pid, handle));

  if (!handle && !info.base && info.init >= main_module_base)
    info.base = main_module_base;
}

bool get_module_handle(pid_t pid, const char *module_name, ModuleInfo *info) {
  uint32_t handle = 0;

  if (pid <= 0 || !module_name || !*module_name ||
      kernel_dynlib_handle(pid, module_name, &handle))
    return false;

  if (info) {
    *info = {};
    read_module(pid, handle, *info);
    copy_text(info->name, sizeof(info->name), module_name, module_name_max);
  }

  return true;
}

#ifdef __ORBIS__

static constexpr uint32_t probe_count = 0x100;
static constexpr uint32_t low_handles = 0x80;
static constexpr uint32_t high_handles = 0x2000;
static constexpr size_t path_max = 256;

static bool read_text(uintptr_t address, char *out, size_t size) {
  size_t length = 0;

  while (length + 1 < size) {
    size_t chunk = 8 - ((address + length) & 7);

    if (chunk > size - 1 - length)
      chunk = size - 1 - length;

    if (kernel_copyout(address + length, out + length, chunk))
      break;

    size_t found = 0;

    while (found < chunk && out[length + found])
      ++found;

    length += found;

    if (found < chunk)
      break;
  }

  out[length] = '\0';

  return length > 0;
}

std::vector<ModuleInfo> list_proc_modules(pid_t pid) {
  std::vector<ModuleInfo> list;

  if (pid <= 0)
    return list;

  for (uint32_t index = 0; index < probe_count; ++index) {
    const uint32_t handle =
        index < low_handles ? index : high_handles + index - low_handles;
    dynlib_obj_t object;
    char path[path_max];

    if (kernel_dynlib_obj(pid, handle, &object) || !object.path ||
        !read_text(object.path, path, sizeof(path)))
      continue;

    ModuleInfo info{};

    read_module(pid, handle, info);
    copy_text(info.name, sizeof(info.name), file_name(path), sizeof(path));
    list.push_back(info);
  }

  return list;
}

#endif

#ifdef __PROSPERO__

static constexpr int sys_dl_get_list = 0x217;
static constexpr int sys_dl_get_info = 0x218;
static constexpr size_t module_limit = 1024;
static constexpr size_t dl_info_size = 4096;
static constexpr size_t dl_info_name_max = 128;

std::vector<ModuleInfo> list_proc_modules(pid_t pid) {
  std::vector<ModuleInfo> list;
  size_t count = 0;

  if (pid <= 0)
    return list;

  syscall(sys_dl_get_list, static_cast<long>(pid), nullptr, 0L, &count);

  if (!count || count > module_limit)
    return list;

  std::vector<uint64_t> handles(count);

  syscall(sys_dl_get_list, static_cast<long>(pid), handles.data(),
          handles.size(), &count);

  if (count > handles.size())
    count = handles.size();

  for (size_t index = 0; index < count; ++index) {
    alignas(8) uint8_t raw[dl_info_size] = {};

    if (syscall(sys_dl_get_info, static_cast<long>(pid), handles[index], raw) <
        0)
      continue;

    ModuleInfo info{};

    read_module(pid, static_cast<uint32_t>(handles[index]), info);
    copy_text(info.name, sizeof(info.name), reinterpret_cast<const char *>(raw),
              dl_info_name_max);
    list.push_back(info);
  }

  return list;
}

#endif
