#!/bin/sh
# Fetches and caches the Alpine minirootfs tarball used as the
# integration-test rootfs fixture. The tarball is sha256-pinned and
# downloaded once into the given cache directory; concurrent invocations
# serialize on a lock file. Extraction is the test suite's job, through
# the library's own tarball provisioner.
#
# Usage: alpine-minirootfs.sh CACHE_DIR
#
# Prints the path of the verified tarball on success.

set -eu

version=3.24.1
branch=v3.24

case "$(uname -m)" in
x86_64)
    arch=x86_64
    sha256=41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081
    ;;
aarch64)
    arch=aarch64
    sha256=f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259
    ;;
*)
    echo "alpine-minirootfs.sh: no pinned fixture for architecture $(uname -m)" >&2
    exit 1
    ;;
esac

cache_dir=${1:?usage: alpine-minirootfs.sh CACHE_DIR}
name="alpine-minirootfs-$version-$arch"
tarball="$cache_dir/$name.tar.gz"
url="https://dl-cdn.alpinelinux.org/alpine/$branch/releases/$arch/$name.tar.gz"

# Fast path: already downloaded and verified.
if [ -f "$tarball" ]; then
    printf '%s\n' "$tarball"
    exit 0
fi

mkdir -p "$cache_dir"
exec 9>"$cache_dir/.lock"
flock 9

# Re-check under the lock: another invocation may have finished the work.
if [ -f "$tarball" ]; then
    printf '%s\n' "$tarball"
    exit 0
fi

if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tarball.part" "$url"
else
    wget -qO "$tarball.part" "$url"
fi

echo "$sha256  $tarball.part" | sha256sum -c - >/dev/null
mv "$tarball.part" "$tarball"

printf '%s\n' "$tarball"
