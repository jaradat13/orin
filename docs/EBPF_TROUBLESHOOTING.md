# 🔧 eBPF Real-Time Streaming Troubleshooting Guide

Orin's real-time eBPF streaming engine (`orin stream`) attaches directly to kernel tracepoints to harvest process creation, connection, and file events via the BPF ring buffer.

Orin operates on a **CO-RE (Compile Once - Run Everywhere)** architecture, which compiles the C program once on a developer/build machine and loads it directly on target systems.

---

## 1. System Requirements Check

Target/production machines have **zero compiler requirements**. They only need the `libbpf` shared library:

- **Debian/Ubuntu:** `sudo apt-get install libbpf1` (or `libbpf0`)
- **RHEL/Rocky/Alma:** `sudo dnf install libbpf`

No kernel headers, clang, or llvm compilation tools are required on runtime machines.

---

## 2. Developer / Build Machine Setup

If you are modifying the eBPF source code ([ebpf/streamer.c](file:///home/musa/orin/ebpf/streamer.c)) and need to compile it to `streamer.bpf.o`, run the setup script with the `--build` flag:

```bash
sudo ./scripts/setup_ebpf.sh --build
```

This will check and install the build toolchain (`clang`, `llvm`, `bpftool`, and `libbpf-dev` / `libbpf-devel`) and generate a local `vmlinux.h`.

---

## 3. Common Errors and Solutions

### ❌ Error: `libbpf shared library is not loaded` / `Could not find system libbpf library`

**Root Cause:** The system `libbpf` shared library is missing on the target host.

**Remediation:**
Install the runtime libraries using your system's package manager:
- **Debian/Ubuntu:** `sudo apt-get install libbpf1` (or `libbpf0`)
- **RHEL/Rocky/Alma:** `sudo dnf install libbpf`

---

### ❌ Error: `Failed to load eBPF program: [Errno 13] Permission denied`

**Root Cause:** Orin's streamer must attach to tracepoints and create maps, which requires root privileges.

**Remediation:**
Ensure you are running the streamer under `sudo` or as `root`:
```bash
sudo orin stream
```

---

### ❌ Error: `BTF is not supported on this kernel` / `CONFIG_DEBUG_INFO_BTF` is missing

**Root Cause:** The target kernel does not support BPF Type Format (BTF) data required for dynamic offset relocation.

**Remediation:**
1. Check if BTF is present:
   ```bash
   ls -la /sys/kernel/btf/vmlinux
   ```
2. If your kernel does not support BTF, you must rely on Orin's standard point-in-time collector (`orin collect`), which parses `/proc` instead of utilizing real-time eBPF streaming.

---

## 4. Kernel Verification Reference

If you need to verify kernel compilation flags on a machine:
```bash
# Check if BPF syscall is enabled
grep CONFIG_BPF_SYSCALL /boot/config-$(uname -r)

# Check if BTF is enabled
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)

# Check if Ring Buffer is supported (requires Kernel >= 5.8)
grep CONFIG_BPF_JIT /boot/config-$(uname -r)
```