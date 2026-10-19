#include "nineS.hpp"
#include "remote.hpp"

#include <cstdint>
#include <cstdlib>
#include <unistd.h>

#ifdef __ORBIS__
#include <ps4/kernel.h>
#endif

#ifdef __PROSPERO__
#include <ps5/kernel.h>
#endif

#ifdef __ORBIS__

static constexpr uint64_t jailbroken_proc_type = 0x3801000000000013ULL;

static bool read_root_credentials(uintptr_t &root_vnode,
                                  uintptr_t &root_prison) {
  uintptr_t init_proc = kernel_get_proc(1);
  uintptr_t init_ucred = 0, init_filedesc = 0;

  if (!init_proc ||
      kernel_copyout(init_proc + 0x40, &init_ucred, sizeof(init_ucred)) ||
      kernel_copyout(init_proc + 0x48, &init_filedesc, sizeof(init_filedesc)) ||
      !init_ucred || !init_filedesc ||
      kernel_copyout(init_ucred + 0x30, &root_prison, sizeof(root_prison)) ||
      kernel_copyout(init_filedesc + 0x18, &root_vnode, sizeof(root_vnode)) ||
      !root_vnode || !root_prison) {
    log_line("[Jail] could not resolve PID 1 root credentials: proc=%#lx "
             "ucred=%#lx filedesc=%#lx vnode=%#lx prison=%#lx\n",
             init_proc, init_ucred, init_filedesc, root_vnode, root_prison);
    return false;
  }

  return true;
}

static bool read_proc_creds(pid_t pid, proc_creds &creds) {
  uintptr_t ucred = kernel_get_proc_ucred(pid);

  if (!ucred) {
    log_line("[Jail] no ucred for PID %d\n", pid);
    return false;
  }

  creds.pid = pid;

  if (kernel_copyout(ucred + 0x04, creds.uid, sizeof(creds.uid)) ||
      kernel_copyout(ucred + 0x14, creds.gid, sizeof(creds.gid)) ||
      kernel_copyout(ucred + 0x58, &creds.proc_type, sizeof(creds.proc_type))) {
    log_line("[Jail] could not read ucred fields for PID %d\n", pid);
    return false;
  }

  int result = kernel_get_ucred_caps(pid, creds.caps);

  if (result) {
    log_line("[Jail] reading sonyCred/procCap for PID %d failed: %d\n", pid,
             result);
    return false;
  }

  creds.prison = kernel_get_ucred_prison(pid);
  creds.currdir = kernel_get_proc_currdir(pid);
  creds.rootdir = kernel_get_proc_rootdir(pid);
  creds.jaildir = kernel_get_proc_jaildir(pid);

  return true;
}

static bool write_proc_creds(pid_t pid, const proc_creds &creds) {
  uintptr_t ucred = kernel_get_proc_ucred(pid);

  if (!ucred)
    return false;

  if (kernel_copyin(creds.uid, ucred + 0x04, sizeof(creds.uid)) ||
      kernel_copyin(creds.gid, ucred + 0x14, sizeof(creds.gid)) ||
      kernel_set_ucred_caps(pid, creds.caps) ||
      kernel_set_ucred_authid(pid, creds.proc_type) ||
      kernel_set_ucred_prison(pid, creds.prison) ||
      kernel_set_proc_currdir(pid, creds.currdir) ||
      kernel_set_proc_rootdir(pid, creds.rootdir) ||
      kernel_set_proc_jaildir(pid, creds.jaildir)) {
    log_line("[Jail] restoring credentials for PID %d failed\n", pid);
    return false;
  }

  return true;
}

static bool same_creds(const proc_creds &a, const proc_creds &b) {
  return !memcmp(a.uid, b.uid, sizeof(a.uid)) &&
         !memcmp(a.gid, b.gid, sizeof(a.gid)) &&
         !memcmp(a.caps, b.caps, sizeof(a.caps)) &&
         a.proc_type == b.proc_type && a.prison == b.prison &&
         a.currdir == b.currdir && a.rootdir == b.rootdir &&
         a.jaildir == b.jaildir;
}

bool jail_process(pid_t pid, proc_creds *old_creds) {
  proc_creds current{};

  return old_creds && old_creds->pid == pid &&
         write_proc_creds(pid, *old_creds) && read_proc_creds(pid, current) &&
         same_creds(current, *old_creds);
}

static bool elevate(pid_t pid, const proc_creds &old_creds) {
  uintptr_t root_vnode = 0, root_prison = 0;

  if (!read_root_credentials(root_vnode, root_prison))
    return false;

  proc_creds elevated = old_creds;

  memset(elevated.uid, 0, sizeof(elevated.uid));
  memset(elevated.gid, 0, sizeof(elevated.gid));
  memset(elevated.caps, 0xff, sizeof(elevated.caps));
  elevated.proc_type = jailbroken_proc_type;
  elevated.prison = root_prison;
  elevated.currdir = root_vnode;
  elevated.rootdir = root_vnode;
  elevated.jaildir = root_vnode;

  if (write_proc_creds(pid, elevated))
    return true;

  if (!write_proc_creds(pid, old_creds))
    log_line("[Jail] rollback failed for PID %d\n", pid);

  return false;
}

proc_creds *jailbreak_process(pid_t pid) {
  auto *old_creds = static_cast<proc_creds *>(calloc(1, sizeof(proc_creds)));

  if (old_creds && pid > 0 && read_proc_creds(pid, *old_creds) &&
      elevate(pid, *old_creds))
    return old_creds;

  free(old_creds);

  return nullptr;
}

#endif

void release_creds(proc_creds *creds) {
#ifdef __ORBIS__
  free(creds);
#else
  delete creds;
#endif
}

uintptr_t set_proc_authid(uintptr_t new_authid) {
  pid_t pid = getpid();
  uintptr_t authid = kernel_get_ucred_authid(pid);

  kernel_set_ucred_authid(pid, new_authid);

  return authid;
}

#ifdef __PROSPERO__

proc_creds *jailbreak_process(pid_t pid) {
  uintptr_t ucred = kernel_get_proc_ucred(pid);

  if (!ucred)
    return nullptr;

  proc_creds *saved = new proc_creds();

  kernel_copyout(ucred, saved->ucred, UCRED_SIZE);
  saved->original_rootdir = kernel_get_proc_rootdir(pid);

  const uint32_t zero = 0;
  const int64_t all_caps = -1;
  const uint8_t attributes = 0x80;

  kernel_copyin(&zero, ucred + 0x04, sizeof(zero));
  kernel_copyin(&zero, ucred + 0x08, sizeof(zero));
  kernel_copyin(&zero, ucred + 0x0C, sizeof(zero));
  kernel_copyin(&zero, ucred + 0x10, sizeof(zero));
  kernel_copyin(&zero, ucred + 0x14, sizeof(zero));
  kernel_copyin(&all_caps, ucred + 0x60, sizeof(all_caps));
  kernel_copyin(&all_caps, ucred + 0x68, sizeof(all_caps));
  kernel_copyin(&attributes, ucred + 0x83, sizeof(attributes));
  kernel_set_proc_rootdir(pid, kernel_get_root_vnode());

  return saved;
}

bool jail_process(pid_t pid, proc_creds *old_creds) {
  uintptr_t ucred = kernel_get_proc_ucred(pid);

  return old_creds && ucred &&
         !kernel_copyin(old_creds->ucred, ucred, UCRED_SIZE) &&
         !kernel_set_proc_rootdir(pid, old_creds->original_rootdir) &&
         kernel_get_proc_ucred(pid) == ucred &&
         kernel_get_proc_rootdir(pid) == old_creds->original_rootdir;
}

#endif
