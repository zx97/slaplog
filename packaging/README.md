# Release packaging

The release workflow produces, for each version:

| Artefact | Target | Built with |
|---|---|---|
| `slaplog-<version>-linux-amd64.tar.gz` | any Linux x86-64 | AlmaLinux 9, `-march=x86-64-v2` |
| `slaplog-<version>-linux-arm64.tar.gz` | any Linux arm64 | AlmaLinux 9, `-march=armv8-a` |
| `slaplog_<version>-1_amd64.deb` | Debian 12+, Ubuntu 22.04+ | same binary, nfpm |
| `slaplog_<version>-1_arm64.deb` | Debian 12+, Ubuntu 22.04+ (arm64) | same binary, nfpm |
| `slaplog-<version>-1.x86_64.rpm` | RHEL 9+, AlmaLinux 9+, Rocky 9+ | same binary, nfpm |
| `slaplog-<version>-1.aarch64.rpm` | RHEL 9+, AlmaLinux 9+, Rocky 9+ (arm64) | same binary, nfpm |
| `SHA256SUMS` | all | `sha256sum` |
| `ghcr.io/zx97/slaplog:<version>` | container, amd64+arm64 | Debian 12 runtime |

The binary is built on **AlmaLinux 9** (glibc 2.34, GCC 11) so it runs on every
current Debian/Ubuntu/RHEL release.  It is never built with `-march=native`:
the instruction-set baseline is explicit, and `-ffp-contract=off` is kept so
the reports stay identical across builds.

## Local build

Requirements:

- `make`, a C++17 compiler, PCRE2, zlib, bzip2, liblzma, nlohmann-json
  (build-time only for the JSON header);
- `nfpm` (<https://github.com/goreleaser/nfpm/releases>) in `PATH`, or
  `NFPM=/path/to/nfpm`;
- `podman` for the container (optional).

```bash
packaging/build-local.sh              # tarball + .deb + .rpm + SHA256SUMS
packaging/build-local.sh --container  # also builds slaplog:<version>
```

The output is in `dist/`.  The local binary is built for the host architecture
with the same baseline flags as CI; a package built on a newer distribution is
still installable elsewhere because only the package metadata is local.

## CI

### GitHub Actions — `.github/workflows/release.yml`

- Triggered by a `v*` tag, or manually (`workflow_dispatch`, with an optional
  version; manual runs build and package but do not publish).
- Two native runners build the baseline binary in an `almalinux:9` container:
  `ubuntu-24.04` (amd64) and `ubuntu-24.04-arm` (arm64).  The container is
  started with `docker run` from the runner, because the AlmaLinux base image
  has neither `git` nor a compiler.
- A packaging job runs `nfpm` for both architectures, writes `SHA256SUMS`,
  creates the GitHub release if it does not exist (notes from `CHANGELOG.md`),
  and uploads the assets.
- A container job builds a multi-arch image with Buildx and pushes it to
  `ghcr.io/zx97/slaplog` (version and `latest`).

### GitLab CI — `.gitlab-ci.yml`

- `package` (tag only): builds amd64, runs `make check`, produces the same
  tarball/.deb/.rpm, and uploads them to the **Generic Package Registry**
  (`/packages/generic/slaplog/<version>/...`).
- `container` (tag only): builds and pushes the amd64 image to the project
  container registry.

## Runtime dependencies

| Format | Packages |
|---|---|
| deb | `libc6 (>= 2.34)`, `libstdc++6 (>= 11)`, `libpcre2-8-0 (>= 10.34)`, `zlib1g`, `libbz2-1.0`, `liblzma5` |
| rpm | `glibc >= 2.34`, `libstdc++ >= 11`, `pcre2`, `zlib`, `bzip2-libs`, `xz-libs` |

The container image installs the same libraries and runs as UID/GID 10001.
Mount the logs read-only, for example:

```bash
podman run --rm -v "$PWD:/logs:ro" ghcr.io/zx97/slaplog:latest -q /logs/access.log
```

## Signing

`SHA256SUMS` is attached to every GitHub release.  Detached GPG signatures are
not produced yet; add a signing step to the release job if the packages are
distributed through a repository.
