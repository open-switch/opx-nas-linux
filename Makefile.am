ACLOCAL_AMFLAGS=-I m4
SUBDIRS = inc

bin_SCRIPTS = scripts/bin/*

pyutilsdir=$(libdir)/opx
pyutils_SCRIPTS = scripts/lib/python/*.py

lib_LTLIBRARIES=libopx_nas_linux.la

libopx_nas_linux_la_SOURCES=src/nas_os_int_utils.c src/nas_os_vlan_utils.c src/db_linux_interface.c src/net_main.cpp src/netlink_tools.c src/db_linux_route.c src/ds_linux_init.c src/ds_interface_name_tools.c src/ds_api_linux_neigh.c src/nas_os_vlan.cpp src/nas_os_lag.c src/nas_os_interface.cpp src/nas_os_stg.cpp src/nas_os_l3.c src/nas_os_ip.cpp src/nas_os_mac.cpp

libopx_nas_linux_la_SOURCES+=src/if/os_interface_cache.cpp src/if/os_interface_lag.cpp src/if/os_interface_vlan.cpp src/if/os_interface.cpp src/if/os_interface_stg.cpp

libopx_nas_linux_la_CPPFLAGS= -D_FILE_OFFSET_BITS=64 -I$(top_srcdir)/inc/opx -I$(top_srcdir)/inc/opx/private -I$(includedir)/opx

libopx_nas_linux_la_CXXFLAGS=-std=c++11

libopx_nas_linux_la_LDFLAGS=-shared -version-info 1:1:0

libopx_nas_linux_la_LIBADD=-lopx_common -lopx_nas_common -lopx_cps_api_common -lopx_logging

systemdconfdir=/lib/systemd/system
systemdconf_DATA = scripts/init/*.service
