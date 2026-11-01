# A foreign-architecture test run

A sandbox whose root filesystem is built for an architecture the host cannot
execute turns that host into a test environment for the other one: build on
x86_64, run the suite in an arm64 userland, on the machine that is already
there. The kernel supplies the mechanism through `binfmt_misc`, which hands a
foreign binary to an interpreter — `qemu-user` — instead of refusing to execute
it. Everything else is a cage as usual.

The [Debian provisioner](debian.md) takes an architecture, so the root comes
from the archive the same way any other does. What is different is that every
process the sandbox runs afterwards is emulated, including the ones the
bootstrap itself runs. The library ships a worked example.

```sh
cross-arch-test --rootfs ./trixie-arm64 --cache ./deb-cache
```

It provisions an arm64 Debian root with a C toolchain, compiles a program inside
it, and runs the program. The compiler, the linker, and the program they produce
are all arm64 binaries on an x86_64 host.

## What the host has to provide

A registered `qemu-user` handler for the target architecture, enabled, and
carrying the **fix-binary** (`F`) flag. On Debian and Ubuntu hosts that is the
`qemu-user-static` and `binfmt-support` packages; the registration then looks
like this:

```text
$ cat /proc/sys/fs/binfmt_misc/qemu-aarch64
enabled
interpreter /usr/libexec/qemu-binfmt/aarch64-binfmt-P
flags: POF
offset 0
```

The `F` flag is the one that matters here, and it is why a foreign sandbox works
at all. Without it the kernel resolves the interpreter's path at execution time,
inside whatever mount namespace and root the process has — and a cage has
pivoted into the target rootfs by then, where `/usr/libexec/qemu-binfmt` does not
exist. With `F` the kernel opens the interpreter at *registration* time and
holds it, so it keeps working wherever the process ends up. Nothing in the
library's launch path touches the registration.

[`foreign_interpreter`] reports what is registered, so a consumer can check
before committing to a bootstrap and tell the three failures apart:

```rust,no_run
use ferroday_cage::provision::debian::foreign_interpreter;

# fn main() {
match foreign_interpreter("arm64") {
    None => println!("run natively, or no handler registered"),
    Some(interpreter) if !interpreter.enabled => {
        println!("qemu-{} is registered but switched off", interpreter.name);
    }
    Some(interpreter) if !interpreter.flags.contains('F') => {
        println!("qemu-{} lacks the fix-binary flag", interpreter.name);
    }
    Some(interpreter) => {
        println!("emulated by {}", interpreter.path.display());
    }
}
# }
```

Those are three different problems with three different fixes — install it,
enable it, re-register it — and a message that collapsed them would send a
reader to the wrong one. The provisioner's own preflight tells them apart too,
before it downloads anything. The example checks on every run all the same,
since a root that already exists is reused without a bootstrap, and its command
needs the handler just as much.

`Interpreter` also carries [`resolved`], the interpreter path canonicalized. The
two are separate facts worth recording separately: the registration usually
names a wrapper that is a symlink to the real binary, and repointing that
symlink changes the interpreter — and so, silently, the compiled output — without
changing the registration. An artifact signature that records provenance wants
both.

## Where the architecture is decided, and where it is not

Three answers, and it is worth knowing which is which.

[`host_architecture`] reports the *host's* Debian architecture, and it comes
from `uname`, not from `std::env::consts::ARCH`. The two differ in a way that
matters: `ARCH` reports what the calling binary was compiled for, and it reports
`powerpc64` for both endiannesses, so it cannot tell `ppc64` from `ppc64el` —
different Debian architectures with incompatible binaries.

[`architecture`] sets the *target*, and defaults to the host's. Nothing above
the provisioner reads it back: a cage is told a root filesystem and a command,
and it neither knows nor asks what either was built for. That is what makes the
foreign case work without a mode of its own.

A **seccomp filter** is the one place a reader might expect an architecture
problem and not find one. A filter gates on the audit architecture of the task
making the syscall, and under `qemu-user` that task is the emulator — a native
binary. The syscalls reaching the kernel are the host's, issued by qemu on the
guest's behalf, so a filter compiled for the host applies exactly as it does to
any other process. There is no translation to get wrong.

What does change is the *set* of syscalls a workload makes. An emulator maps the
guest's address space, keeps threads of its own, and turns guest calls into host
calls that need not correspond one to one, so a policy narrow enough for a
native workload can be too narrow for the same workload emulated. That is a
property of the emulator rather than a defect.

In practice the curated policy is wide enough: `cross-arch-test --harden`
compiles and runs the probe under it unchanged. The caveat is worth keeping for
a caller-authored allowlist, which is narrow by construction and was written
against whatever syscalls the workload made natively.

## When the binaries cannot run at all

An architecture with no `qemu-user` handler — or a host with no `binfmt_misc` —
can still have a root laid out for it, just not configured. [`extract_only`]
unpacks every package and writes the dpkg metadata without running a single
target binary, producing a tree that is complete on disk and unconfigured. It is
what a cross-build wants when it needs headers and libraries rather than a
working userland, and it is the documented alternative the preflight's failure
message points at.

[`resolve`] and [`available`] need neither a handler nor an identity map either,
since they talk to the archive and run nothing. Asking what an architecture's
archive contains works from any host.

## Running it

```sh
# Provision an arm64 root and run the built-in probe in it:
cargo run --example cross-arch-test --features debian,hardening -- \
    --rootfs ./trixie-arm64 --cache ./deb-cache

# The same, under the curated seccomp policy:
cargo run --example cross-arch-test --features debian,hardening -- \
    --rootfs ./trixie-arm64 --harden

# A shell in the foreign root, for looking around:
cargo run --example cross-arch-test --features debian,hardening -- \
    --rootfs ./trixie-arm64 -- /bin/bash
```

The first run reports the interpreter it will use, bootstraps the root, and then
compiles and runs the probe:

```text
cross-arch-test: arm64 runs through /usr/libexec/qemu-binfmt/aarch64-binfmt-P (flags POF)
cross-arch-test: provisioned ./trixie-arm64 for arm64
uname -m inside the cage: aarch64
readelf: machine is AArch64
probe: built for arm64, 64-bit pointers, little-endian
probe: all checks passed
```

The probe asserts what it was *built* for rather than reporting what it
observes, which is what makes it a test rather than a demonstration. Its
architecture comes from the compiler's own predefined macros, so a toolchain
that quietly produced host binaries fails to satisfy it; `readelf` reads the
machine out of the ELF header before the program is ever executed, which is the
check a running program cannot make about itself.

The bootstrap is the slow part, and it is slow because of emulation rather than
download: every `dpkg` invocation and every maintainer script in the
configuration wave is an arm64 binary running under the interpreter. The root is
published once and reused, so only the first run pays for it.

[`architecture`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.architecture
[`available`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.available
[`extract_only`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.DebianBuilder.html#method.extract_only
[`foreign_interpreter`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/fn.foreign_interpreter.html
[`host_architecture`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/fn.host_architecture.html
[`resolve`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Debian.html#method.resolve
[`resolved`]: https://docs.rs/ferroday-cage/latest/ferroday_cage/provision/debian/struct.Interpreter.html#structfield.resolved
