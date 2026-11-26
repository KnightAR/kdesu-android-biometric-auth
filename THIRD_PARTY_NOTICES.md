# Licensing and upstream provenance

The original Android application, Python host/verifier/configurator, native
launcher, build scripts and documentation are MIT licensed; see [LICENSE](LICENSE).
This does not relicense the upstream code represented in the KDE patches.

- `packaging/kde-repo/` contains Gentoo packaging derived from Gentoo Authors'
  GPL-2.0-only ebuilds and the kdesu-only split patch by Andreas Sturmlechner.
- The kdesu integration patch targets KDE `kde-cli-tools` **6.7.2**. Modified and
  added kdesu C++ files retain their Artistic-2.0 notices, including Geert Jansen's
  existing copyright. The upstream distribution contains other licensed components;
  consult its per-file SPDX notices when redistributing a complete build.
- The Codex SVG included inside the patch is from **LobeHub**, copyright 2023,
  under MIT. Its complete notice is retained as `kdesu/icons/LICENSE.codex` when
  the patch is applied. Inclusion does not imply endorsement.
- The Android application bundles the **Protocol Buffers Java lite runtime**
  (`com.google.protobuf:protobuf-javalite` 4.36.2, copyright 2008 Google Inc.),
  under the BSD 3-Clause license in
  [BSD-3-Clause-protobuf.txt](LICENSES/BSD-3-Clause-protobuf.txt). `build.sh`
  downloads it from Maven Central and checks its pinned SHA-256. The desktop uses
  the distribution's `protoc` and Python `protobuf` packages; code generated from
  `proto/navi.proto` belongs to this project.
- [Artistic-2.0](LICENSES/Artistic-2.0.txt) and
  [GPL-2.0-only](LICENSES/GPL-2.0-only.txt) texts are retained from the upstream
  KDE release archive.

Upstream: <https://invent.kde.org/plasma/kde-cli-tools>.
This is a downstream project, not an official KDE release or Android security product.
