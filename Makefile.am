#
# Copyright (c) 2019 Dell Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
# THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT
# LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS
# FOR A PARTICULAR PURPOSE, MERCHANTABLITY OR NON-INFRINGEMENT.
#
# See the Apache Version 2.0 License for specific language governing
# permissions and limitations under the License.
#

ACLOCAL_AMFLAGS=-I m4
SUBDIRS = inc

bin_SCRIPTS = scripts/bin/*

pyutilsdir=$(libdir)/opx
pyutils_SCRIPTS = scripts/lib/python/*.py

lib_LTLIBRARIES=libopx_nas_linux.la

COMMON_HARDEN_FLAGS=-fexceptions -fstack-protector-strong -fstack-protector-all -D_FORTIFY_SOURCE=2 -Wall -Wformat -Wformat-security -Werror
C_HARDEN_FLAGS=-Wimplicit-function-declaration
LD_HARDEN_FLAGS=-Wl,-z,defs -Wl,-z,now

libopx_nas_linux_la_SOURCES=src/nas_os_int_utils.c src/nas_os_vlan_utils.c src/db_linux_interface.c src/net_main.cpp src/netlink_tools.c src/db_linux_route.c src/ds_linux_init.c src/ds_interface_name_tools.c src/ds_api_linux_neigh.c src/nas_os_vlan.cpp src/nas_os_lag.c src/nas_os_interface.cpp src/nas_os_stg.cpp src/nas_os_l3.c src/nas_os_ip.cpp src/nas_os_mac.cpp src/netlink_stats.cpp src/if/os_interface_macvlan.cpp src/nas_os_mcast_snoop.cpp src/nas_os_vrf.cpp

libopx_nas_linux_la_SOURCES+=src/if/os_interface_cache.cpp src/if/os_interface_lag.cpp src/if/os_interface_vlan.cpp src/if/os_interface.cpp src/if/os_interface_stg.cpp src/if/os_interface_loopback.cpp src/if/os_interface_bridge.cpp src/if/os_interface_cache_utils.cpp src/if/os_interface_vxlan.cpp \
src/nas_os_lpbk.cpp \
src/if/os_interface_mgmt.cpp


libopx_nas_linux_la_CPPFLAGS= -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/inc/opx -I$(top_srcdir)/inc/opx/private -I$(includedir)/opx $(COMMON_HARDEN_FLAGS)

libopx_nas_linux_la_CXXFLAGS=-std=c++11

libopx_nas_linux_la_CFLAGS=$(C_HARDEN_FLAGS)

libopx_nas_linux_la_LDFLAGS=-shared -version-info 1:1:0 $(LD_HARDEN_FLAGS)

libopx_nas_linux_la_LIBADD=-lopx_common -lopx_nas_common -lopx_cps_api_common -lopx_logging -lpthread

systemdconfdir=/lib/systemd/system
systemdconf_DATA = scripts/init/*.service
