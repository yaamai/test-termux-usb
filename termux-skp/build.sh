# http(s) link to package home page.
TERMUX_PKG_HOMEPAGE=https://github.com/yaamai/test-termux-usb

# One-line, short package description.
TERMUX_PKG_DESCRIPTION="OpenSSH security key provider for termux"

# License.
# Use SPDX identifier: https://spdx.org/licenses/
TERMUX_PKG_LICENSE="MIT"

# Who cares about package.
# Specify yourself (Github nick, or name + email) if you wish to maintain the
# package, fix its bugs, etc. Otherwise specify "@termux".
# Please note that unofficial repositories are not allowed to reference @termux
# as their maintainer.
TERMUX_PKG_MAINTAINER="@yaamai"

# Version.
TERMUX_PKG_VERSION=0.0.3

TERMUX_PKG_DEPENDS="libfido2,libusb,hidapi-libusb"

TERMUX_PKG_SKIP_SRC_EXTRACT=true
TERMUX_PKG_BUILD_IN_SRC=true

termux_step_get_source() {
	mkdir -p $TERMUX_PKG_SRCDIR
	cd $TERMUX_PKG_SRCDIR

  # pwd
  # env
  cp -rp $TERMUX_PKG_BUILDER_DIR/* $TERMUX_PKG_SRCDIR

}


# URL to archive with source code.
#TERMUX_PKG_SRCURL=https://mirrors.kernel.org/gnu/ed/ed-${TERMUX_PKG_VERSION}.tar.lz

# SHA-256 checksum of the source code archive.
#TERMUX_PKG_SHA256=ad4489c0ad7a108c514262da28e6c2a426946fb408a3977ef1ed34308bdfd174
