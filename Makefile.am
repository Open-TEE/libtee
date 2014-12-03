# Makefile.am -- Process this file with automake to produce Makefile.in

# Include libtool macros
ACLOCAL_AMFLAGS = -I m4

# Shared libraries
lib_LTLIBRARIES  = 

# Public header files
include_HEADERS = \
	include/com_protocol.h \
	include/tee_client_api.h \
	include/tee_logging.h \
	include/tee_shared_data_types.h

# Include module-specific Makefiles
include src/Makemodule.am
