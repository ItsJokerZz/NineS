#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>
#include <vector>

void set_logger(void (*sink)(const char *line));

enum class ElfError { None, Invalid, Crt, Load, Relocate, Unresolved };

struct ElfMap {
  bool crt = false;
  const char *const *modules = nullptr;
  unsigned module_count = 0;
  void (*module)(const char *name, bool found, unsigned handle) = nullptr;
  void (*unresolved)(const char *symbol, unsigned searched) = nullptr;
  void (*protect)(uintptr_t offset, size_t size, int prot) = nullptr;
  unsigned imports = 0, unresolved_count = 0, searched = 0, routed = 0;
  intptr_t base = 0, support = 0;
  size_t size = 0, support_size = 0;
  const char *route_error = nullptr, *route_call = nullptr;
  unsigned route_read = 0;
  int route_errno = 0;
  ElfError error = ElfError::None;
};

bool elf_valid(const void *elf, size_t size);

bool elf_self_linking(const void *elf, size_t size);

uintptr_t map_elf(pid_t pid, const void *elf, size_t size, ElfMap &map);

bool inject_elf(pid_t pid, const void *elf, size_t size, bool jailbreak = true);

bool inject_elf(pid_t pid, const void *elf, bool jailbreak) = delete;

#ifdef __ORBIS__

struct proc_creds {
  pid_t pid;
  uint32_t uid[3], gid[2];
  uint8_t caps[16];
  uint64_t proc_type;
  intptr_t prison, currdir, rootdir, jaildir;
};

#endif

#ifdef __PROSPERO__

#define PTRACE_AUTHID 0x4800000000010003
#define UCRED_SIZE 0x200

struct proc_creds {
  uint8_t ucred[UCRED_SIZE];
  intptr_t original_rootdir;
};

#endif

uintptr_t set_proc_authid(uintptr_t new_authid);

struct proc_creds *jailbreak_process(pid_t pid);

bool jail_process(pid_t pid, struct proc_creds *old_creds);

void release_creds(struct proc_creds *creds);

enum class PluginFailure {
  None,
  BadPath,
  NoLoader,
  NoThread,
  TimedOut,
  Rejected
};

struct PluginCall {
  bool done;
  bool entered;
  int result;
  PluginFailure failure;
};

bool plugin_loaded(pid_t pid, const char *path);

PluginCall load_plugin(pid_t pid, const char *path,
                       unsigned timeout_ms = 10000);

PluginCall unload_plugin(pid_t pid, const char *path,
                         unsigned timeout_ms = 10000);

constexpr size_t proc_name_max = 32;
constexpr size_t module_name_max = 128;

struct ProcInfo {
  pid_t pid;
  char name[proc_name_max];
  char thread_name[proc_name_max];
};

struct ModuleInfo {
  uint32_t handle;
  uintptr_t base, entry, init, fini;
  char name[module_name_max];
};

std::vector<ProcInfo> list_procs();

pid_t find_proc_by_name(const char *name);

bool get_proc_by_pid(pid_t pid, ProcInfo &info);

bool get_module_handle(pid_t pid, const char *module_name,
                       ModuleInfo *info = nullptr);

std::vector<ModuleInfo> list_proc_modules(pid_t pid);
