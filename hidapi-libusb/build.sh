# http(s) link to package home page.
TERMUX_PKG_HOMEPAGE=https://github.com/libusb/hidapi

# One-line, short package description.
TERMUX_PKG_DESCRIPTION="A Simple cross-platform library for communicating with HID devices"

# License.
# Use SPDX identifier: https://spdx.org/licenses/
TERMUX_PKG_LICENSE="GPL-3.0-only"
TERMUX_PKG_LICENSE_FILE=LICENSE-gpl3.txt

# Who cares about package.
# Specify yourself (Github nick, or name + email) if you wish to maintain the
# package, fix its bugs, etc. Otherwise specify "@termux".
# Please note that unofficial repositories are not allowed to reference @termux
# as their maintainer.
TERMUX_PKG_MAINTAINER="yaamai"

# Version.
TERMUX_PKG_VERSION=0.14.0
TERMUX_PKG_DEPENDS="libusb"

#TERMUX_PKG_SKIP_SRC_EXTRACT=true
#TERMUX_PKG_BUILD_IN_SRC=true

TERMUX_PKG_SRCURL=https://github.com/libusb/hidapi/archive/refs/tags/hidapi-0.14.0.tar.gz
TERMUX_PKG_SHA256=a5714234abe6e1f53647dd8cba7d69f65f71c558b7896ed218864ffcf405bcbd

#TERMUX_PKG_EXTRA_CONFIGURE_ARGS="-DUSE_HIDAPI=OFF -DUSE_WINHELLO=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TOOLS=OFF -DNFC_LINUX=OFF"

