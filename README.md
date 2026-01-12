# WASP: Workload-Aware Self-Replicating Page Tables

A Linux 6.4 kernel implementation of NUMA-aware page table replication with workload-aware steering capabilities.

## Overview

Mitosis+WASP addresses the performance bottleneck of remote memory accesses during page table walks on NUMA systems. By replicating page tables across NUMA nodes and steering CR3 loads to node-local replicas, this implementation significantly reduces TLB miss latency for memory-intensive workloads.

### Key Features

- **Full Page Table Replication**: Replicates all levels (PGD, P4D, PUD, PMD, PTE) across configured NUMA nodes
- **Automatic CR3 Steering**: Context switches automatically use node-local page table replicas
- **Workload-Aware Steering**: Fine-grained control over which physical nodes use which replicas
- **Lockless Page Table Cache**: ABA-resistant lockless cache for fast page table allocation
- **Inheritance Support**: Child processes can inherit replication configuration
- **Comprehensive Statistics**: Real-time monitoring via `/proc/mitosis/`

## Requirements

- x86_64 architecture
- NUMA system with 2+ nodes
- Linux kernel 6.4
- **Not compatible with:**
  - Page Table Isolation (PTI/KPTI) - Meltdown mitigation must be disabled
  - Systems vulnerable to Meltdown should not use this feature

## Building

### Kernel Configuration

Enable the feature in your kernel config:

```
CONFIG_PARAVIRT_XXL=y
CONFIG_PGTABLE_REPLICATION=y
CONFIG_NUMA=y
CONFIG_SMP=y
```

### Build Commands

```bash
make menuconfig  # Enable PGTABLE_REPLICATION under Processor type and features
make -j$(nproc)
make modules_install
make install
```

### Boot Parameters

Add `mitosis` to kernel command line to auto-enable replication for all new processes:

```
GRUB_CMDLINE_LINUX="mitosis"
```

## Usage

### prctl() Interface

#### Enable Replication

```c
#include <sys/prctl.h>

#define PR_SET_PGTABLE_REPL     100
#define PR_GET_PGTABLE_REPL     101

// Enable on all online nodes
prctl(PR_SET_PGTABLE_REPL, 1, 0, 0, 0);

// Enable on specific nodes (bitmask: nodes 0 and 1)
prctl(PR_SET_PGTABLE_REPL, 0x3, 0, 0, 0);

// Enable for another process (by PID)
prctl(PR_SET_PGTABLE_REPL, 1, target_pid, 0, 0);

// Disable replication
prctl(PR_SET_PGTABLE_REPL, 0, 0, 0, 0);
```

#### Query Status

```c
long result = prctl(PR_GET_PGTABLE_REPL, 0, 0, 0, 0);
// Returns bitmask of nodes with replicas, or 0 if disabled
```

#### Steering Control

```c
#define PR_SET_PGTABLE_REPL_STEERING    104
#define PR_GET_PGTABLE_REPL_STEERING    105

#define NUMA_NODE_COUNT 8

// Steering matrix: physical_node -> replica_node
// -1 = auto (use local node)
int steering[NUMA_NODE_COUNT] = {-1, -1, -1, -1, -1, -1, -1, -1};

// Force node 0 CPUs to use node 1's replica
steering[0] = 1;

prctl(PR_SET_PGTABLE_REPL_STEERING, steering, 0, 0, 0);

// Query current steering
int current[NUMA_NODE_COUNT];
prctl(PR_GET_PGTABLE_REPL_STEERING, current, 0, 0, 0);
```

### Sysctl Interface

```bash
# View/set auto-enable mode
# -1 = default (no special handling)
#  0 = force all page tables to node 0
#  1 = auto-enable for new processes
echo 1 > /proc/mitosis/mode

# View/set inheritance
# -1 = disabled, 1 = enabled
echo 1 > /proc/mitosis/inherit
```

### Monitoring

```bash
# Overall system status
cat /proc/mitosis/status

# List active replicated processes
cat /proc/mitosis/active

# Historical statistics
cat /proc/mitosis/history

# Page table cache status
cat /proc/mitosis/cache

# Clear history
echo -1 > /proc/mitosis/history

# Populate cache (N pages per node)
echo 100 > /proc/mitosis/cache

# Drain cache
echo -1 > /proc/mitosis/cache

# Reset cache statistics
echo -2 > /proc/mitosis/cache
```

## Architecture

### Page Table Replica Linking

Replicas are linked in a circular list via `struct page->pt_replica`:

```
Node 0 PTE ──→ Node 1 PTE ──→ Node 2 PTE  ──┐
     ↑                                      │
     └──────────────────────────────────────┘
```

### CR3 Selection Flow

```
     Context Switch
           │
           ▼
  ┌─────────────────┐
  │ Read local node │
  └────────┬────────┘
           │
           ▼
┌─────────────────────┐
│ Check steering[node]│
└──────────┬──────────┘
           │
      ┌────┴────┐
      │   -1?   │
      └────┬────┘
       ┌───┴────┐
   Yes │        │  No
       │        │
       ▼        ▼
   ┌─────┐ ┌──────────────┐
   │Local│ │ Steered node │
   └──┬──┘ └──────┬───────┘
      │           │
      ▼           ▼
┌─────────────────────────┐
│ Load pgd_replicas[node] │
└─────────────────────────┘
            │
            ▼
       Write to CR3
```

### Lockless Cache Design

Uses tagged pointers for ABA-resistant lock-free operations:

```
Tagged pointer: [16-bit tag][48-bit canonical address]

Push: CAS(head, old_head, new_page | incremented_tag)
Pop:  CAS(head, old_head, next | incremented_tag)
```

## Statistics Explained

### /proc/mitosis/status

| Field | Description |
|-------|-------------|
| CR3 writes | Total CR3 register writes |
| Replica uses | Times a non-primary replica was used |
| Primary uses | Times the primary PGD was used |
| Replica hit rate | Percentage of CR3 writes using replicas |
| PTE/PMD/PUD/P4D/PGD sets | Replicated write operations per level |
| Cache hits/misses | Page table cache performance |

### /proc/mitosis/active

Shows currently running processes with replication enabled, including:
- PID/TGID
- Duration
- Number of replicated nodes

### /proc/mitosis/history

Historical records of completed replication sessions with:
- Peak memory usage per node
- TLB shootdown statistics
- Replica counts at each page table level

### PCID Disabled

This implementation disables PCID (Process Context ID) and INVPCID to ensure TLB flushes occur on every CR3 write. This is necessary for correctness when switching between replicas.

## API Reference

### Kernel Functions

```c
// Enable replication for an mm_struct
int pgtable_repl_enable(struct mm_struct *mm, nodemask_t nodes);

// Disable replication
void pgtable_repl_disable(struct mm_struct *mm);

// Initialize mm for replication
int pgtable_repl_init_mm(struct mm_struct *mm);

// Enable for external process (via task_work)
int pgtable_repl_enable_external(struct task_struct *target, nodemask_t nodes);
```

### Data Structures

```c
// Per-mm replication state (in mm_struct)
bool repl_pgd_enabled;
nodemask_t repl_pgd_nodes;
pgd_t *pgd_replicas[NUMA_NODE_COUNT];
int repl_steering[NUMA_NODE_COUNT];

// Per-page replica linking (in struct page)
struct page *pt_replica;
```

## References

- [Mitosis: Transparently Self-Replicating Page-Tables for Large-Memory Machines](https://dl.acm.org/doi/10.1145/3373376.3378468) (ASPLOS 2020)
- [WASP: Workload-Aware Self-Replicating Page Tables](https://dl.acm.org/doi/10.1145/3620665.3640369) (ASPLOS '24)

## License

GPL-2.0 (as part of the Linux kernel)

## Version

- Kernel Base: Linux 6.4
- Extraversion: `-wasp`

## AI attestation

This code was developed with AI assistance. For a full protocol containing the implementation assistance during the development of Mitosis and WASP, see [here](https://github.com/julianw1010/thesis-protocol).
