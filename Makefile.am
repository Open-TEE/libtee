ACLOCAL_AMFLAGS = -I m4
AM_CPPFLAGS = -Iinclude
lib_LTLIBRARIES = lib_tee.la
lib_tee_la_LDFLAGS = -lm -lcrypt
lib_tee_la_SOURCES = src/open_emu_ipc/tee_client_api_emu_ipc.c src/open_emu_ipc/list.c src/open_emu_ipc/utils.c
lib_tee_la_LIBADD = -luuid -lrt -lcrypto
METASOURCES = AUTO
