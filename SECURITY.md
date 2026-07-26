# Security policy

ferroday-cage is a sandbox. A defect in it can mean code that was supposed to
stay inside gets out, so security reports are handled separately from ordinary
bugs.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub's [private
vulnerability reporting](https://github.com/gregordinary/ferroday-cage/security/advisories/new)
for this repository, which opens a draft advisory visible only to you and the
maintainers.

Please include, as far as you can:

- what the sandbox was configured to do (a profile, or the builder calls);
- what escaped, was reached, or was observed that should not have been;
- the kernel version, distribution, and architecture;
- whether the host had unprivileged user namespaces, Landlock, and seccomp
  available, and the Landlock ABI if you know it;
- a reproducer, if you have one.

You will get an acknowledgement within a few days. Once a fix exists, the
advisory names the reporter unless you ask otherwise.

## What is in scope

The library's job is to build the boundary it says it builds. In scope:

- **Containment bypass.** Code inside the sandbox reaching a host path, host
  process, or host resource the configuration did not grant.
- **A restriction that does not restrict.** A configured Landlock grant,
  seccomp filter, capability drop, or resource limit that is silently not
  applied, applied more permissively than configured, or escapable.
- **Identity-map defects.** A sandbox acting as an id outside its configured
  map, or a map established differently from what was requested.
- **Provisioning containment.** An archive or package that writes outside the
  destination during extraction, or a signature or digest check that can be
  bypassed.
- **Memory safety.** Any unsoundness in the crate's `unsafe` core, or any way
  safe consumer code can trigger undefined behavior.

## What is not in scope

- **The default profile as a boundary against hostile code.** It is not one,
  and the guide says so. Confinement of untrusted code is opt-in through the
  [hardening](https://gregordinary.github.io/ferroday-cage/hardening.html)
  layer; a report that untrusted code did something the default profile never
  claimed to prevent is a documentation question, not a vulnerability.
- **Resource exhaustion outside the per-process limits.** The library sets
  `setrlimit` values on request; cgroup governance and disk quotas are the
  host's, as the hardening chapter states.
- **A trusted profile doing what a trusted profile may.** A profile loaded
  through the trusted path is code-equivalent configuration and can bind any
  host path. Loading an untrusted profile through that path is the caller's
  bug; `RestrictedProfile` is the path for one.
- **Host misconfiguration.** A kernel without Landlock, without seccomp, or
  with unprivileged user namespaces disabled is reported as such rather than
  silently degraded — that reporting is the correct behavior.

If you are unsure which side of the line a finding falls on, report it
privately and we will work it out.

## Supported versions

The crate is pre-1.0 and under active development. Fixes land on the latest
release; older versions are not patched.
