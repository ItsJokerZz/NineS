#include "nineS.hpp"
#include "remote.hpp"

#include <cerrno>
#include <cstdint>
#include <cstring>
#include <elf.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>

#ifdef __ORBIS__
#include <ps4/kernel.h>
#endif

#ifdef __PROSPERO__
#include <ps5/kernel.h>
#include <pthread.h>
#include <sys/syscall.h>
#endif

extern "C" {
#include "elfldr.h"
}

#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT R_X86_64_JMP_SLOT
#endif

namespace {

constexpr unsigned kMaxModules = 16;
constexpr size_t kMaxImage = 256u * 1024u * 1024u;

const char *const kHostModules[] = {
    "libSceLibcInternal.sprx", "libkernel_sys.sprx", "libSceSystemService.sprx",
    "libkernel.sprx", "libkernel_web.sprx"};

const char *const kRuntimeMarkers[] = {"Unable to resolve '%s'",
                                       "/system/priv/lib/%s"};

bool in_file(uint64_t offset, uint64_t bytes, size_t size) {
  return offset <= size && bytes <= size - offset;
}

bool contains(const uint8_t *data, size_t size, const char *text) {
  const size_t length = strlen(text);

  while (size >= length) {
    const uint8_t *hit =
        static_cast<const uint8_t *>(memchr(data, text[0], size - length + 1));

    if (!hit)
      return false;

    if (!memcmp(hit, text, length))
      return true;

    size -= hit + 1 - data;
    data = hit + 1;
  }

  return false;
}

uintptr_t page_floor(uintptr_t value) {
  return value & ~static_cast<uintptr_t>(PAGE_SIZE - 1);
}

uintptr_t page_ceil(uintptr_t value) {
  return (value + (PAGE_SIZE - 1)) & ~static_cast<uintptr_t>(PAGE_SIZE - 1);
}

int protection(uint32_t flags) {
  return ((flags & PF_R) ? PROT_READ : 0) | ((flags & PF_W) ? PROT_WRITE : 0) |
         ((flags & PF_X) ? PROT_EXEC : 0);
}

int page_protection(const Elf64_Phdr *phdr, unsigned count, uintptr_t page) {
  int prot = 0;

  for (unsigned i = 0; i < count; ++i) {
    if (phdr[i].p_type != PT_LOAD || !phdr[i].p_memsz)
      continue;

    uintptr_t start = page_floor(phdr[i].p_vaddr);
    uintptr_t end = page_ceil(phdr[i].p_vaddr + phdr[i].p_memsz);

    if (page >= start && page < end)
      prot |= protection(phdr[i].p_flags);
  }

  return prot;
}

bool image_span(const Elf64_Ehdr *ehdr, const Elf64_Phdr *phdr, uintptr_t &low,
                uintptr_t &high) {
  uint64_t lowest = UINT64_MAX, highest = 0;

  for (unsigned i = 0; i < ehdr->e_phnum; ++i) {
    if (phdr[i].p_type != PT_LOAD || !phdr[i].p_memsz)
      continue;

    if (phdr[i].p_vaddr > UINT64_MAX - phdr[i].p_memsz)
      return false;

    if (phdr[i].p_vaddr < lowest)
      lowest = phdr[i].p_vaddr;

    if (phdr[i].p_vaddr + phdr[i].p_memsz > highest)
      highest = phdr[i].p_vaddr + phdr[i].p_memsz;
  }

  if (lowest == UINT64_MAX || highest > UINT64_MAX - (PAGE_SIZE - 1))
    return false;

  low = page_floor(lowest);
  high = page_ceil(highest);

  return true;
}

struct Layout {
  const uint8_t *elf;
  size_t size;
  pid_t pid;
  intptr_t base;
  size_t span;
  uintptr_t min_vaddr;
};

bool resolve(const Layout &l, ElfMap &map, const Elf64_Shdr *sections,
             unsigned section_count, const Elf64_Shdr *relocations,
             const Elf64_Rela &rel, const unsigned *handles,
             unsigned handle_count) {
  if (relocations->sh_link >= section_count)
    return false;

  const Elf64_Shdr *table = &sections[relocations->sh_link];

  if (table->sh_entsize != sizeof(Elf64_Sym) || table->sh_offset % 8 ||
      !in_file(table->sh_offset, table->sh_size, l.size) ||
      table->sh_link >= section_count)
    return false;

  const Elf64_Shdr *strings = &sections[table->sh_link];
  const uint64_t index = ELF64_R_SYM(rel.r_info);

  if (index >= table->sh_size / sizeof(Elf64_Sym) ||
      !in_file(strings->sh_offset, strings->sh_size, l.size))
    return false;

  const Elf64_Sym *sym =
      reinterpret_cast<const Elf64_Sym *>(l.elf + table->sh_offset) + index;

  if (sym->st_name >= strings->sh_size)
    return false;

  const char *name =
      reinterpret_cast<const char *>(l.elf + strings->sh_offset) + sym->st_name;

  if (!memchr(name, 0, strings->sh_size - sym->st_name))
    return false;

  uintptr_t address = 0;
  bool missing = false;

  if (sym->st_shndx == SHN_ABS) {
    address = sym->st_value;
  } else if (sym->st_shndx != SHN_UNDEF) {
    if (sym->st_value < l.min_vaddr || sym->st_value - l.min_vaddr >= l.span)
      return false;

    address = l.base + sym->st_value - l.min_vaddr;
  } else {
    for (unsigned i = 0; i < handle_count && !address; ++i)
      address = kernel_dynlib_dlsym(l.pid, handles[i], name);

    if (!address && ELF64_ST_BIND(sym->st_info) != STB_WEAK) {
      if (map.unresolved)
        map.unresolved(name, handle_count);

      ++map.unresolved_count;
      missing = true;
    }
  }

  if (missing)
    return true;

  address += rel.r_addend;

  return !pt_copyin(l.pid, &address, l.base + rel.r_offset - l.min_vaddr,
                    sizeof(address));
}

constexpr size_t kThunkSize = 32;
constexpr size_t kThunkPage = 0x4000;
constexpr unsigned kMaxRouted = 16;
constexpr unsigned kNameRoom = 64;
constexpr unsigned kCodeScan = 4096;
constexpr unsigned kCodeStep = 64;

const char *const kRoutedCalls[] = {"pthread_setspecific"};

constexpr unsigned kRoutedCount = sizeof(kRoutedCalls) / sizeof(*kRoutedCalls);

struct Dynamic {
  uint64_t symtab, strtab, strsz, rela, relasz, jmprel, pltrelsz;
};

struct Routed {
  uint64_t entry;
  Elf64_Rela rela;
  unsigned call;
};

const uint8_t *image_data(const uint8_t *elf, size_t size,
                          const Elf64_Phdr *phdr, unsigned count,
                          uint64_t vaddr, uint64_t bytes) {
  for (unsigned i = 0; i < count; ++i) {
    if (phdr[i].p_type != PT_LOAD || vaddr < phdr[i].p_vaddr)
      continue;

    const uint64_t into = vaddr - phdr[i].p_vaddr;

    if (into <= phdr[i].p_filesz && bytes <= phdr[i].p_filesz - into &&
        in_file(phdr[i].p_offset + into, bytes, size))
      return elf + phdr[i].p_offset + into;
  }

  return nullptr;
}

bool read_dynamic(const uint8_t *elf, size_t size, const Elf64_Ehdr *ehdr,
                  const Elf64_Phdr *phdr, Dynamic &dyn) {
  dyn = {};

  for (unsigned i = 0; i < ehdr->e_phnum; ++i) {
    if (phdr[i].p_type != PT_DYNAMIC)
      continue;

    if (!in_file(phdr[i].p_offset, phdr[i].p_filesz, size))
      return false;

    for (uint64_t at = 0; at + sizeof(Elf64_Dyn) <= phdr[i].p_filesz;
         at += sizeof(Elf64_Dyn)) {
      Elf64_Dyn entry;

      memcpy(&entry, elf + phdr[i].p_offset + at, sizeof(entry));

      switch (entry.d_tag) {
      case DT_SYMTAB:
        dyn.symtab = entry.d_un.d_ptr;
        break;
      case DT_STRTAB:
        dyn.strtab = entry.d_un.d_ptr;
        break;
      case DT_STRSZ:
        dyn.strsz = entry.d_un.d_val;
        break;
      case DT_RELA:
        dyn.rela = entry.d_un.d_ptr;
        break;
      case DT_RELASZ:
        dyn.relasz = entry.d_un.d_val;
        break;
      case DT_JMPREL:
        dyn.jmprel = entry.d_un.d_ptr;
        break;
      case DT_PLTRELSZ:
        dyn.pltrelsz = entry.d_un.d_val;
        break;
      case DT_NULL:
        return true;
      }
    }

    return true;
  }

  return false;
}

int routed_call(const char *name, uint64_t room) {
  const size_t length = strnlen(name, room);

  for (unsigned i = 0; i < kRoutedCount; ++i)
    if (length == strlen(kRoutedCalls[i]) &&
        !memcmp(name, kRoutedCalls[i], length))
      return static_cast<int>(i);

  return -1;
}

void collect_routed(const uint8_t *elf, size_t size, const Elf64_Phdr *phdr,
                    unsigned count, const Dynamic &dyn, uint64_t table,
                    uint64_t bytes, Routed *found, unsigned &routed) {
  for (uint64_t at = 0; at + sizeof(Elf64_Rela) <= bytes && routed < kMaxRouted;
       at += sizeof(Elf64_Rela)) {
    const uint8_t *raw =
        image_data(elf, size, phdr, count, table + at, sizeof(Elf64_Rela));

    if (!raw)
      return;

    Elf64_Rela rela;

    memcpy(&rela, raw, sizeof(rela));

    const uint32_t type = ELF64_R_TYPE(rela.r_info);

    if (type != R_X86_64_GLOB_DAT && type != R_X86_64_JMP_SLOT &&
        type != R_X86_64_64)
      continue;

    const uint8_t *symbol =
        image_data(elf, size, phdr, count,
                   dyn.symtab + ELF64_R_SYM(rela.r_info) * sizeof(Elf64_Sym),
                   sizeof(Elf64_Sym));

    if (!symbol)
      continue;

    Elf64_Sym sym;

    memcpy(&sym, symbol, sizeof(sym));

    if (sym.st_name >= dyn.strsz)
      continue;

    uint64_t room = dyn.strsz - sym.st_name;

    if (room > kNameRoom)
      room = kNameRoom;

    const char *name = reinterpret_cast<const char *>(
        image_data(elf, size, phdr, count, dyn.strtab + sym.st_name, room));
    const int call = name ? routed_call(name, room) : -1;

    if (call >= 0)
      found[routed++] = {table + at, rela, static_cast<unsigned>(call)};
  }
}

const char *return_gadget(pid_t pid, intptr_t function, uintptr_t &gadget,
                          unsigned &have) {
  uint8_t code[kCodeScan] = {};

  have = 0;

  while (have < sizeof(code) &&
         !pt_copyout(pid, function + have, code + have, kCodeStep))
    have += kCodeStep;

  if (!have)
    return "the code of the call cannot be read";

  unsigned set = 0;

  for (unsigned i = 0; i < have; ++i)
    set += code[i] != 0;

  if (!set)
    return "the code of the call reads as zeros";

  for (unsigned i = 1; i < have; ++i) {
    if (code[i] == 0xc3 && code[i - 1] == 0x5d) {
      gadget = function + i;

      return nullptr;
    }
  }

  for (unsigned i = 0; i < have; ++i) {
    if (code[i] == 0xc3) {
      gadget = function + i;

      return nullptr;
    }
  }

  return "no return instruction near the start of the call";
}

#ifdef __PROSPERO__

constexpr unsigned kStubSteps = 8;

const char *stepped_return(pid_t pid, uintptr_t &gadget) {
  const intptr_t stub = pt_resolve(pid, "HoLVWNanBBc");
  struct reg saved, run;

  if (stub <= 0)
    return "the system call stub cannot be resolved";

  if (pt_getregs(pid, &saved))
    return "the registers cannot be read";

  run = saved;
  run.r_rip = stub + 0xa;
  run.r_rax = SYS_getpid;

  if (pt_setregs(pid, &run))
    return "the registers cannot be set";

  const char *result = "no return instruction ran while stepping the stub";

  for (unsigned i = 0; i < kStubSteps; ++i) {
    const uintptr_t before = run.r_rip;

    if (pt_step(pid) || pt_getregs(pid, &run)) {
      result = "the stub cannot be stepped";

      break;
    }

    if (run.r_rsp > saved.r_rsp) {
      gadget = before;
      result = nullptr;

      break;
    }
  }

  pt_setregs(pid, &saved);

  return result;
}

#endif

const char *find_return(pid_t pid, intptr_t function, uintptr_t &gadget,
                        unsigned &have) {
  have = 0;

#ifdef __PROSPERO__
  const char *stepped = stepped_return(pid, gadget);

  if (!stepped)
    return nullptr;
#endif

  return return_gadget(pid, function, gadget, have);
}

void write_thunk(uint8_t *thunk, uintptr_t function, uintptr_t gadget) {
  static const uint8_t code[16] = {0x48, 0x8b, 0x05, 17, 0, 0, 0, 0x50,
                                   0x50, 0xff, 0x25, 1,  0, 0, 0, 0x90};

  memset(thunk, 0, kThunkSize);
  memcpy(thunk, code, sizeof(code));
  memcpy(thunk + 16, &function, sizeof(function));
  memcpy(thunk + 24, &gadget, sizeof(gadget));
}

bool route_calls(pid_t pid, const uint8_t *elf, size_t size, intptr_t load_bias,
                 ElfMap &map) {
  const Elf64_Ehdr *ehdr = reinterpret_cast<const Elf64_Ehdr *>(elf);
  const Elf64_Phdr *phdr =
      reinterpret_cast<const Elf64_Phdr *>(elf + ehdr->e_phoff);
  Dynamic dyn;

  if (!read_dynamic(elf, size, ehdr, phdr, dyn) || !dyn.symtab || !dyn.strtab ||
      !dyn.strsz)
    return true;

  Routed found[kMaxRouted];
  unsigned routed = 0;

  collect_routed(elf, size, phdr, ehdr->e_phnum, dyn, dyn.rela, dyn.relasz,
                 found, routed);
  collect_routed(elf, size, phdr, ehdr->e_phnum, dyn, dyn.jmprel, dyn.pltrelsz,
                 found, routed);

  if (!routed)
    return true;

  const intptr_t page = map_executable(pid, kThunkPage);

  if (page <= 0) {
    map.route_error = "the stub page cannot be mapped";
    map.route_errno = errno;

    return true;
  }

  uint8_t block[kRoutedCount * kThunkSize] = {};
  bool used[kRoutedCount] = {};

  for (unsigned i = 0; i < routed; ++i)
    used[found[i].call] = true;

  for (unsigned i = 0; i < kRoutedCount; ++i) {
    if (!used[i])
      continue;

    const intptr_t function = pt_resolve(pid, kRoutedCalls[i]);
    uintptr_t gadget = 0;

    map.route_error = function > 0
                          ? find_return(pid, function, gadget, map.route_read)
                          : "the call cannot be resolved";

    if (map.route_error) {
      map.route_errno = errno;
      map.route_call = kRoutedCalls[i];
      pt_munmap(pid, page, kThunkPage);

      return true;
    }

    write_thunk(block + i * kThunkSize, function, gadget);
  }

  if (pt_copyin(pid, block, page, sizeof(block))) {
    map.route_error = "the stub cannot be written";
    map.route_errno = errno;
    pt_munmap(pid, page, kThunkPage);

    return true;
  }

  for (unsigned i = 0; i < routed; ++i) {
    Elf64_Rela patched = found[i].rela;
    const intptr_t thunk = page + found[i].call * kThunkSize;

    patched.r_info = R_X86_64_RELATIVE;
    patched.r_addend = thunk - load_bias +
                       (ELF64_R_TYPE(found[i].rela.r_info) == R_X86_64_64
                            ? found[i].rela.r_addend
                            : 0);

    if (pt_copyin(pid, &patched, load_bias + found[i].entry, sizeof(patched))) {
      pt_munmap(pid, page, kThunkPage);

      return false;
    }
  }

  map.support = page;
  map.support_size = kThunkPage;
  map.routed = routed;

  return true;
}

} // namespace

bool elf_valid(const void *image, size_t size) {
  const uint8_t *elf = static_cast<const uint8_t *>(image);

  if (!elf || size < sizeof(Elf64_Ehdr) ||
      elfldr_sanity_check(const_cast<uint8_t *>(elf), size))
    return false;

  const Elf64_Ehdr *ehdr = reinterpret_cast<const Elf64_Ehdr *>(elf);

  if (ehdr->e_phentsize != sizeof(Elf64_Phdr) || ehdr->e_phoff % 8 ||
      !in_file(ehdr->e_phoff, ehdr->e_phnum * sizeof(Elf64_Phdr), size) ||
      (ehdr->e_shnum &&
       (ehdr->e_shentsize != sizeof(Elf64_Shdr) || ehdr->e_shoff % 8 ||
        !in_file(ehdr->e_shoff, ehdr->e_shnum * sizeof(Elf64_Shdr), size))))
    return false;

  const Elf64_Phdr *phdr =
      reinterpret_cast<const Elf64_Phdr *>(elf + ehdr->e_phoff);
  uintptr_t low = 0, high = 0;

  if (!image_span(ehdr, phdr, low, high) || high - low > kMaxImage)
    return false;

  const Elf64_Shdr *shdr =
      ehdr->e_shnum ? reinterpret_cast<const Elf64_Shdr *>(elf + ehdr->e_shoff)
                    : nullptr;

  for (unsigned i = 0; i < ehdr->e_shnum; ++i) {
    if (shdr[i].sh_type != SHT_RELA)
      continue;

    if (shdr[i].sh_entsize != sizeof(Elf64_Rela) || shdr[i].sh_offset % 8 ||
        !in_file(shdr[i].sh_offset, shdr[i].sh_size, size))
      return false;

    const Elf64_Rela *rela =
        reinterpret_cast<const Elf64_Rela *>(elf + shdr[i].sh_offset);

    for (uint64_t j = 0; j < shdr[i].sh_size / sizeof(Elf64_Rela); ++j) {
      if (ELF64_R_TYPE(rela[j].r_info) != R_X86_64_NONE &&
          (rela[j].r_offset < low ||
           rela[j].r_offset - low > high - low - sizeof(uint64_t)))
        return false;
    }
  }

  return true;
}

bool elf_self_linking(const void *image, size_t size) {
  if (!image || !size)
    return false;

  for (const char *marker : kRuntimeMarkers)
    if (!contains(static_cast<const uint8_t *>(image), size, marker))
      return false;

  return true;
}

uintptr_t map_elf(pid_t pid, const void *image, size_t size, ElfMap &map) {
  map.imports = map.unresolved_count = map.searched = map.routed = 0;
  map.route_error = nullptr;
  map.route_call = nullptr;
  map.route_errno = 0;
  map.route_read = 0;
  map.base = map.support = 0;
  map.size = map.support_size = 0;
  map.error = ElfError::Invalid;

  if (!elf_valid(image, size))
    return 0;

  const uint8_t *elf = static_cast<const uint8_t *>(image);
  const Elf64_Ehdr *ehdr = reinterpret_cast<const Elf64_Ehdr *>(elf);

  if (ehdr->e_type != ET_DYN && !(map.crt && ehdr->e_type == ET_EXEC))
    return 0;

  const Elf64_Phdr *phdr =
      reinterpret_cast<const Elf64_Phdr *>(elf + ehdr->e_phoff);
  const Elf64_Shdr *shdr =
      ehdr->e_shnum ? reinterpret_cast<const Elf64_Shdr *>(elf + ehdr->e_shoff)
                    : nullptr;

  const char *const *modules = map.modules ? map.modules : kHostModules;
  unsigned module_count = map.modules
                              ? map.module_count
                              : sizeof(kHostModules) / sizeof(*kHostModules);

  if (module_count > kMaxModules)
    return 0;

  unsigned handles[kMaxModules], handle_count = 0;

  if (!map.crt) {
    for (unsigned i = 0; i < module_count; ++i) {
      unsigned handle;
      bool found = !kernel_dynlib_handle(pid, modules[i], &handle);

      if (found)
        handles[handle_count++] = handle;

      if (map.module)
        map.module(modules[i], found, found ? handle : 0);
    }

    map.searched = handle_count;

    for (unsigned i = 0; i < ehdr->e_shnum; ++i) {
      if (shdr[i].sh_size &&
          (shdr[i].sh_type == SHT_INIT_ARRAY ||
           shdr[i].sh_type == SHT_FINI_ARRAY || (shdr[i].sh_flags & SHF_TLS))) {
        map.error = ElfError::Crt;

        return 0;
      }
    }
  }

  uintptr_t min_vaddr = 0, max_vaddr = 0;

  image_span(ehdr, phdr, min_vaddr, max_vaddr);

  const intptr_t entry = elfldr_load(pid, const_cast<uint8_t *>(elf));

  if (!entry) {
    map.error = ElfError::Load;

    return 0;
  }

  Layout layout{elf,
                size,
                pid,
                entry - static_cast<intptr_t>(ehdr->e_entry) +
                    static_cast<intptr_t>(min_vaddr),
                max_vaddr - min_vaddr,
                min_vaddr};
  ElfError error = ElfError::None;
  unsigned imports = 0;

  if (map.crt &&
      !route_calls(pid, elf, size, entry - static_cast<intptr_t>(ehdr->e_entry),
                   map)) {
    pt_munmap(pid, layout.base, layout.span);
    map.error = ElfError::Relocate;

    return 0;
  }

  for (unsigned i = 0; i < ehdr->e_shnum && !map.crt && error == ElfError::None;
       i++) {
    if (shdr[i].sh_type != SHT_RELA)
      continue;

    const Elf64_Rela *rela =
        reinterpret_cast<const Elf64_Rela *>(elf + shdr[i].sh_offset);

    for (size_t j = 0;
         j < shdr[i].sh_size / sizeof(Elf64_Rela) && error == ElfError::None;
         j++) {
      switch (ELF64_R_TYPE(rela[j].r_info)) {
      case R_X86_64_NONE:
      case R_X86_64_RELATIVE:
        break;
      case R_X86_64_GLOB_DAT:
      case R_X86_64_JMP_SLOT:
      case R_X86_64_64:
        if (!resolve(layout, map, shdr, ehdr->e_shnum, &shdr[i], rela[j],
                     handles, handle_count))
          error = ElfError::Relocate;

        ++imports;
        break;
      default:
        error = ElfError::Relocate;
        break;
      }
    }
  }

  map.imports = imports;

  if (error == ElfError::None && map.unresolved_count)
    error = ElfError::Unresolved;

  int saved = errno;

  if (error != ElfError::None) {
    pt_munmap(pid, layout.base, layout.span);
    map.error = error;
    errno = saved;

    return 0;
  }

  for (uintptr_t page = min_vaddr; page < max_vaddr;) {
    int prot = page_protection(phdr, ehdr->e_phnum, page);
    uintptr_t end = page + PAGE_SIZE;

    while (end < max_vaddr && page_protection(phdr, ehdr->e_phnum, end) == prot)
      end += PAGE_SIZE;

    if (map.protect)
      map.protect(page - min_vaddr, end - page, prot);

    page = end;
  }

  map.error = ElfError::None;
  map.base = layout.base;
  map.size = layout.span;

  return entry;
}

static const char *error_text(ElfError error) {
  switch (error) {
  case ElfError::None:
    return "no error";
  case ElfError::Invalid:
    return "not an image this loader can map";
  case ElfError::Crt:
    return "init or fini arrays or TLS in an image without the SDK runtime";
  case ElfError::Load:
    return "mapping the segments failed";
  case ElfError::Relocate:
    return "a relocation could not be applied";
  case ElfError::Unresolved:
    return "imports missing from the modules the process has loaded";
  }

  return "unknown error";
}

static void log_routing(const ElfMap &map) {
  if (map.routed)
    log_line("Routed %u libkernel call(s) of the ELF through return stubs\n",
             map.routed);
  else if (map.route_error)
    log_line("Could not route %s: %s (read %u bytes, errno %d); the ELF runs "
             "unrouted\n",
             map.route_call ? map.route_call : "the libkernel calls",
             map.route_error, map.route_read, map.route_errno);
}

#ifdef __ORBIS__

static constexpr size_t kImageStack = 4u * 1024u * 1024u;

static void log_unresolved(const char *symbol, unsigned searched) {
  log_line("Unable to resolve %s in %u modules\n", symbol, searched);
}

static bool start_image(pid_t pid, const void *elf, size_t size,
                        bool jailbreak) {
  proc_creds *creds = nullptr;

  if (jailbreak) {
    creds = jailbreak_process(pid);

    if (!creds) {
      log_line("Unable to jailbreak process %d, aborting injection...\n", pid);

      return false;
    }
  }

  bool started = false;
  intptr_t base = 0, support = 0;
  size_t mapped = 0, support_size = 0;
  uintptr_t entry = 0;

  {
    Attachment target(pid);

    if (target.held) {
      ElfMap map;

      map.crt = elf_self_linking(elf, size);
      map.unresolved = log_unresolved;
      entry = map_elf(pid, elf, size, map);
      base = map.base;
      mapped = map.size;
      support = map.support;
      support_size = map.support_size;

      if (!entry)
        log_line("Unable to map the ELF into process %d: %s\n", pid,
                 error_text(map.error));
      else
        log_routing(map);
    } else {
      log_line("Error attaching into PID: %d\n", pid);
    }
  }

  if (entry) {
    const uint64_t args[6]{};

    started = remote_spawn(pid, entry, args, kImageStack);

    if (!started) {
      log_line("Unable to start a thread in process %d\n", pid);

      Attachment target(pid);

      if (target.held) {
        pt_munmap(pid, base, mapped);

        if (support)
          pt_munmap(pid, support, support_size);
      }
    }
  }

  if (creds) {
    jail_process(pid, creds);
    release_creds(creds);
  }

  return started;
}

#endif

#ifdef __PROSPERO__

using elf_entry_t = int (*)(void *);
using pthread_create_t = int (*)(pthread_t *, const pthread_addr_t *,
                                 void *(*)(void *), void *);

struct StagerArgs {
  elf_entry_t entry;
  void *payload_args;
  pthread_create_t pthread_create;
};

int __attribute__((section(".stager_shellcode$1"))) stager(StagerArgs *args) {
  pthread_t thread;

  args->pthread_create(&thread, 0, (void *(*)(void *))args->entry,
                       args->payload_args);
  __asm__("int3");

  return 0;
}

int __attribute__((section(".stager_shellcode$2"))) stager_end() { return 0; }

static intptr_t remote_copy(pid_t pid, const void *data, size_t size,
                            int prot) {
  intptr_t address = pt_mmap(pid, 0, size, PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

  if (address <= 0)
    return 0;

  if (prot != (PROT_READ | PROT_WRITE))
    kernel_mprotect(pid, address, size, prot);

  pt_copyin(pid, data, address, size);

  return address;
}

static void unmap_image(pid_t pid, const ElfMap &map) {
  pt_munmap(pid, map.base, map.size);

  if (map.support)
    pt_munmap(pid, map.support, map.support_size);
}

static bool start_elf(pid_t pid, const void *elf, size_t size, bool jailbreak) {
  StagerArgs args{};
  args.pthread_create = (pthread_create_t)pt_resolve(pid, "pthread_create");

  log_line("[+] Loading ELF on %d...[+]\n", pid);

  if (!args.pthread_create) {
    log_line("[-] pthread_create is unavailable in %d! [-]\n", pid);
    return false;
  }

  ElfMap map;

  map.crt = true;

  const uintptr_t entry = map_elf(pid, elf, size, map);

  if (!entry) {
    log_line("[-] Failed to load ELF: %s! [-]\n", error_text(map.error));
    return false;
  }

  log_routing(map);

  intptr_t payload_args = elfldr_payload_args(pid);

  log_line("[+] ELF entrypoint: %#02lx | Payload Args: %#02lx [+]\n", entry,
           payload_args);

  args.entry = (elf_entry_t)entry;
  args.payload_args = (void *)payload_args;

  intptr_t code = remote_copy(pid, (const void *)&stager,
                              (uintptr_t)&stager_end - (uintptr_t)&stager,
                              PROT_READ | PROT_WRITE | PROT_EXEC);

  if (!code) {
    log_line("Unable to allocate bootstrap code, injection aborted!\n");
    unmap_image(pid, map);
    return false;
  }

  log_line("[+] Bootstrap code allocated at %#02lx [+]\n", code);

  intptr_t data = remote_copy(pid, &args, sizeof(args), PROT_READ | PROT_WRITE);

  if (!data) {
    log_line("Unable to allocate bootstrap data, injection aborted!\n");
    unmap_image(pid, map);
    return false;
  }

  log_line("[+] Triggering entrypoint... [+]\n");

  proc_creds *creds = nullptr;

  if (jailbreak) {
    creds = jailbreak_process(pid);

    if (!creds) {
      log_line("Unable to jailbreak process %d, aborting injection...\n", pid);
      unmap_image(pid, map);
      return false;
    }
  }

  const uint64_t stager_args[6] = {static_cast<uint64_t>(data)};
  intptr_t stager_result;

  pt_call(pid, code, stager_args, &stager_result);
  sleep(1);

  if (creds) {
    jail_process(pid, creds);
    release_creds(creds);
  }

  return true;
}

static bool start_image(pid_t pid, const void *elf, size_t size,
                        bool jailbreak) {
  const uintptr_t previous = set_proc_authid(PTRACE_AUTHID);
  bool started = false;

  log_line("[+] Elevating injector from authid %#lx...[+]\n", previous);

  if (pt_attach(pid) < 0) {
    log_line("Error attaching into PID: %d\n", pid);
  } else {
    log_line("[+] Attached to %d! [+]\n", pid);

    started = start_elf(pid, elf, size, jailbreak);

    pt_detach(pid, 0);
    log_line("[+] ELF injection finished! [+]\n");
    log_line("[+] Detached [+]\n");
  }

  if (!jailbreak)
    set_proc_authid(previous);

  return started;
}

#endif

bool inject_elf(pid_t pid, const void *elf, size_t size, bool jailbreak) {
  if (!elf_valid(elf, size)) {
    log_line("The ELF is not an image this loader can map\n");

    return false;
  }

  return start_image(pid, elf, size, jailbreak);
}
