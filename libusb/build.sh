# http(s) link to package home page.
TERMUX_PKG_HOMEPAGE=https://github.com/libusb/libusb

# One-line, short package description.
TERMUX_PKG_DESCRIPTION="A cross-platform library to access USB devices"

# License.
# Use SPDX identifier: https://spdx.org/licenses/
TERMUX_PKG_LICENSE="LGPL-2.1-only"
TERMUX_PKG_LICENSE_FILE=COPYING

# Who cares about package.
# Specify yourself (Github nick, or name + email) if you wish to maintain the
# package, fix its bugs, etc. Otherwise specify "@termux".
# Please note that unofficial repositories are not allowed to reference @termux
# as their maintainer.
TERMUX_PKG_MAINTAINER="yaamai"

# Version.
TERMUX_PKG_VERSION=1.0.27

#TERMUX_PKG_SKIP_SRC_EXTRACT=true
#TERMUX_PKG_BUILD_IN_SRC=true

TERMUX_PKG_SRCURL=https://github.com/libusb/libusb/releases/download/v1.0.27/libusb-1.0.27.tar.bz2
TERMUX_PKG_SHA256=ffaa41d741a8a3bee244ac8e54a72ea05bf2879663c098c82fc5757853441575

# in termux, udev enumeration not works
TERMUX_PKG_EXTRA_CONFIGURE_ARGS="--disable-udev"


