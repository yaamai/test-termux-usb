# http(s) link to package home page.
TERMUX_PKG_HOMEPAGE=https://github.com/Yubico/libfido2

# One-line, short package description.
TERMUX_PKG_DESCRIPTION="Provides library functionality for FIDO2, including communication with a device over USB or NFC."

# License.
# Use SPDX identifier: https://spdx.org/licenses/
TERMUX_PKG_LICENSE="BSD-2-Clause"
TERMUX_PKG_LICENSE_FILE=LICENSE

# Who cares about package.
# Specify yourself (Github nick, or name + email) if you wish to maintain the
# package, fix its bugs, etc. Otherwise specify "@termux".
# Please note that unofficial repositories are not allowed to reference @termux
# as their maintainer.
TERMUX_PKG_MAINTAINER="yaamai"

# Version.
TERMUX_PKG_VERSION=0.1.1

TERMUX_PKG_DEPENDS="libcrypt,hidapi-libusb,libcbor"

#TERMUX_PKG_SKIP_SRC_EXTRACT=true
#TERMUX_PKG_BUILD_IN_SRC=true

TERMUX_PKG_SRCURL=https://github.com/Yubico/libfido2/archive/refs/tags/1.14.0.zip
TERMUX_PKG_SHA256=8329721ea5e94e4146e7c5f9c45c7bce8126e7942449fa197c634f74abdbc922

TERMUX_PKG_EXTRA_CONFIGURE_ARGS="-DUSE_HIDAPI=ON -DUSE_WINHELLO=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TOOLS=OFF -DNFC_LINUX=OFF -DHIDAPI_SUFFIX=-libusb"


termux_step_pre_configure() {
  bash
  # based on https://github.com/Yubico/libfido2/pull/571/files
  # cp -rp $TERMUX_PKG_BUILDER_DIR/fix-android-build.patch $TERMUX_PKG_SRCDIR
  # patch -N -f -s -p1 -i fix-android-build.patch || true
}
