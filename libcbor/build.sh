# http(s) link to package home page.
TERMUX_PKG_HOMEPAGE=https://github.com/pjk/libcbor

# One-line, short package description.
TERMUX_PKG_DESCRIPTION="Provides library functionality for FIDO2, including communication with a device over USB or NFC."

# License.
# Use SPDX identifier: https://spdx.org/licenses/
TERMUX_PKG_LICENSE="MIT"

# Who cares about package.
# Specify yourself (Github nick, or name + email) if you wish to maintain the
# package, fix its bugs, etc. Otherwise specify "@termux".
# Please note that unofficial repositories are not allowed to reference @termux
# as their maintainer.
TERMUX_PKG_MAINTAINER="yaamai"

# Version.
TERMUX_PKG_VERSION=0.12.0

#TERMUX_PKG_DEPENDS=

#TERMUX_PKG_SKIP_SRC_EXTRACT=true
#TERMUX_PKG_BUILD_IN_SRC=true

TERMUX_PKG_SRCURL=https://github.com/PJK/libcbor/archive/refs/tags/v0.12.0.tar.gz
TERMUX_PKG_SHA256=5368add109db559f546d7ed10f440f39a273b073daa8da4abffc83815069fa7f
TERMUX_PKG_EXTRA_CONFIGURE_ARGS="-DWITH_EXAMPLES=OFF"



