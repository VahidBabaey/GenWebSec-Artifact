# Hardware

All reported experiments ran on a single host. There is no cluster, no cloud
instance, and no distribution of work across machines. Values below were read
from the live system on 2026-09-14, not transcribed from the paper.

## Host

| Property | Value |
| --- | --- |
| CPU | Intel(R) Core(TM) i9-14900K |
| Logical processors visible to the experiment | 32 |
| Memory allocated to the Linux environment | 26 GB |
| Memory reported inside Linux | 26,669,144 kB (`MemTotal`) |
| Swap | 8 GB |
| Host OS | Windows 11 |
| Experiment OS | Ubuntu 22.04.5 LTS under WSL2 |

Commands used: `grep -m1 'model name' /proc/cpuinfo`, `nproc`,
`grep MemTotal /proc/meminfo`, `free -h`.

## WSL configuration

The experiments do not run under a default WSL configuration. Three settings
matter for reproduction, and all three are deliberate.

```ini
[wsl2]
kernel=C:\Users\<user>\wsl-kernels\kernel-6.6-wsl2510
memory=26GB
swap=8GB
pageReporting=false

[experimental]
autoMemoryReclaim=disabled
sparseVhd=false
```

**The pinned kernel is the important one.** The stock WSL 6.18.x kernel deadlocks
on per-VMA locking during process fork and teardown. In this workload that
manifested as Apache wedging during reload-heavy defense runs, and in the worst
case as a kernel panic. Since the hardening loop reloads Apache after every
accepted rule, the failure was frequent enough to make long runs unusable.

The fix was to pin the last pre-6.18 stable LTS kernel, 6.6.87.2, extracted from
the official WSL 2.5.10 msixbundle. Removing the `kernel=` line restores the
stock kernel and reintroduces the deadlock.

`autoMemoryReclaim=disabled` and `pageReporting=false` disable the periodic
memory-reclaim machinery that races with the same locking path.

## Practical notes for reproduction

- A reproduction does **not** need this exact CPU. Nothing in the method depends
  on core count; more cores shorten wall-clock time and nothing else.
- A reproduction on native Linux does not need any of the WSL settings above.
  They exist to work around a WSL-specific kernel defect.
- Memory headroom does matter in one place. The XSS validity oracle drives a
  real Chromium instance per iteration. Running that alongside Apache, MySQL, and
  two containers is what the 26 GB allocation is sized for.
- Timing figures reported in the paper, namely generation time, rule-validation
  time, and the deployed request-processing measurements, are specific to this
  host and should not be expected to transfer.

## Execution dates

See `execution-dates.md`.
