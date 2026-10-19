# NineS
A C++ library for John Törnblom's PS4/PS5 Payload SDKs that works on other processes: it injects ELF images, loads and unloads plugins, lists processes and their modules, and handles credentials.

| Console | SDK | Archive |
| --- | --- | --- |
| PS4 | [ps4-payload-sdk](https://github.com/ps4-payload-dev/sdk) | `build/ps4/libnineS.a` |
| PS5 | [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk) | `build/ps5/libnineS.a` |

## Requirements
- [lib-ps-ptrace](https://github.com/ItsJokerZz/lib-ps-ptrace): headers to build, `libptrace.a` to link.
- elfldr, which maps the ELF images. Its headers are needed to build and its `elfldr.c` has to be linked into your payload.
  - PS4: [ps4-elfldr](https://github.com/ItsJokerZz/ps4-elfldr), `expose-load` branch.
  - PS5: [ps5-elfldr](https://github.com/ItsJokerZz/ps5-elfldr), `expose-load` branch.

## Building
```sh
export PS4_PAYLOAD_SDK=/opt/ps4-payload-sdk
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk

make          # every console whose SDK variable is set
make ps4      # or: make ps5
make clean
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `PTRACE_DIR` | `../lib-ps-ptrace` | lib-ps-ptrace checkout |
| `ELFLDR_DIR` | `../ps4-elfldr` or `../ps5-elfldr` | elfldr checkout |
| `BUILD` | `build/<platform>` | Output directory |
| `OPT` | `-O2` | Optimisation flags |
| `DEBUG` | unset | Adds `-g` |

## Using
Add `include` and the lib-ps-ptrace headers to the include path, and link `libnineS.a` before `libptrace.a`.

```cpp
#include <nineS.hpp>

set_logger([](const char *line) { fputs(line, stderr); });

pid_t pid = find_proc_by_name("SceShellUI");

inject_elf(pid, image.data(), image.size());
```

The library never prints on its own; without a logger its diagnostics are dropped. Calls attach to the target with ptrace, so a process that is already traced fails to attach. Nothing here is thread safe.

## Functions
| Function | What it does |
| --- | --- |
| `set_logger(sink)` | Sets where diagnostics go |
| `elf_valid(elf, size)` | Checks that an image can be mapped safely |
| `elf_self_linking(elf, size)` | True for images built with the Payload SDK |
| `map_elf(pid, elf, size, map)` | Maps an ELF into a process and returns its entry point |
| `inject_elf(pid, elf, size, jailbreak)` | Maps an ELF and starts it on a new thread |
| `load_plugin`, `unload_plugin`, `plugin_loaded` | Plugin modules |
| `list_procs`, `find_proc_by_name`, `get_proc_by_pid` | Process lookup |
| `list_proc_modules`, `get_module_handle` | Module lookup in a process |
| `jailbreak_process`, `jail_process`, `release_creds`, `set_proc_authid` | Credentials |

The signatures are the same on both consoles.

### ELF images
`inject_elf` takes any image built with the Payload SDK, C or C++. The SDK's startup code loads the libraries, resolves the imports and runs the constructors itself, so nineS only maps the image and starts it on a new thread (4 MiB stack on PS4). Other images must be position independent `ET_DYN` without init or fini arrays or TLS; nineS resolves their imports against the modules the target already has.

Inside a game, libkernel looks up the module of whoever calls `pthread_setspecific`, and a mapped image has none, which crashes C++ images (`std::thread`, exceptions). nineS fixes this by pointing that import at a small stub it writes into the target, so libkernel sees a return address of its own. If the stub cannot be set up the image still starts, unrouted, and the logger says why (`ElfMap::route_error`). Only `pthread_setspecific` is routed so far.

`map_elf` reports through an `ElfMap`; the caller must hold a ptrace stop on the target.

| Field | Meaning |
| --- | --- |
| `crt` | Image has the SDK startup code; skip import and constructor handling |
| `modules`, `module_count` | Modules to resolve imports against, up to 16 |
| `module`, `unresolved`, `protect` | Optional callbacks for modules looked up, missing imports and protected ranges |
| `base`, `size` | Where the image landed |
| `support`, `support_size` | Stub page added to the target; unmap it with the image |
| `routed`, `route_error`, `route_call` | Imports routed through stubs, or why routing was skipped |
| `error` | `ElfError::None`, or why mapping failed |

### Plugins
`load_plugin` loads a module with `sceKernelLoadStartModule` and calls its `plugin_load` export if it has one. `unload_plugin` calls `plugin_unload`, then `sceKernelStopUnloadModule`. Both return a `PluginCall` (`done`, `entered`, `result`, `failure`) and wait up to `timeout_ms` (10 seconds by default).

- A module the loader refuses reports `Rejected`, with the loader's code in `result`.
- If the target dies during the call, the call reports `NoThread`.
- Unloading does not undo what a plugin changed. A plugin that leaves hooks in the game takes the game down.
- On PS4 a plugin must be the signed SELF build. ftpsrv turns a SELF into a plain ELF when you download it, and a copy made that way is refused with `0x80020008`.

### Credentials
`jailbreak_process` returns the credentials it replaced and `jail_process` restores them. Pass the result to `release_creds` when you are done. `set_proc_authid` sets the caller's authid and returns the old one.

### PS5 differences
- The injector's authid is raised for the call and restored afterwards (kept raised when `jailbreak` is true), because ptrace calls against a game fail without it.
- Executable pages are mapped read/write and then made executable with `kernel_mprotect`.
- libkernel's code cannot be read, so the `ret` for the stub comes from single-stepping the system call stub that lib-ps-ptrace uses.

## Credits
- [buzzer-re/NineS](https://github.com/buzzer-re/NineS), the PS5 ELF injector this grew out of, and the [write-up](https://reversing.codes/posts/PlayStation-5-ELF-Injection/).
- [elfldr](https://github.com/ps5-payload-dev/elfldr) and the Payload SDKs by John Törnblom (GPL-3.0-or-later).
