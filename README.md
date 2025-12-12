# XDP IP Blacklist Firewall

## Overview

This repository provides a simple, high-performance firewall utilizing **eXpress Data Path (XDP)** and **eBPF** (extended Berkeley Packet Filter).

The firewall logic runs directly in the kernel's network driver path, dropping packets from blacklisted source IP addresses defined via a dynamic map controlled by the userspace loader.

## 💡 Key Concepts

* **eBPF:** A technology that allows safe execution of custom programs inside the Linux kernel without needing to modify kernel code or load modules.
* **XDP:** A high-performance hook point that executes eBPF programs at the earliest possible stage—right when the NIC driver receives a packet . This minimizes overhead for tasks like packet dropping.
* **eBPF Maps:** Shared memory structures (like a hash table) used for communication between the userspace application and the kernel-running eBPF program. *(The `ip_blacklist` map is used here.)*

## 🛠️ Project Components

| File | Role | Description |
| :--- | :--- | :--- |
| `firewall_kern.c` | **Kernel Code** (eBPF) | Contains the XDP logic to check the packet's source IP against the blacklist map and return `XDP_DROP` if blocked. |
| `firewall_user.c` | **Userspace Code** | Loads the eBPF program, attaches it to the interface, and inserts the target IP into the `ip_blacklist` map. |
| `Makefile` | **Build Script** | Configured for **ARM64** architecture, handles compilation and skeleton generation (`firewall_kern.skel.h`). |

## ⚙️ Building the Project (ARM64)

This project is configured for **ARM64** systems.

### Prerequisites

You need `clang`, `llvm`, `libbpf-dev`, `gcc`, `make`, and `bpftool` installed.

```bash
# Example for Debian/Ubuntu-based systems
sudo apt update
sudo apt install clang llvm libbpf-dev gcc make bpftool