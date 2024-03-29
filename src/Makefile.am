
# The following version numbers are:  current:revision:age
#
# See also: http://sources.redhat.com/autobook/autobook/autobook_91.html
#
# Current - number of the current interface of the library
# Revision - implementation number of most recent interface
# Age - number of previous additional interfaces supported by this library
#
# Libtool uses the following calculation for Linux:
#
#    major = current - age
#    suffix = major.age.revision
#
# Therefore a libtool version of 1.4.0 will translate to a filename of:
#    libbarry.so.1.0.4
#
# Other operating systems just use current.revision, most of the time,
# and age is only used to subtract from current.
#
# Therefore, if you are careful never to increment the major version
# unless there is an incompatible break, you can get away with a
# two digit version number, and leave age as 0, always.
#
# Only ever increment the first 2 numbers in this version:
# The first number represents libmajor, the second libminor.
# So version 0.17.1 will look like 17:1:0
LIB_BARRY_VERSION = @BARRY_MAJOR@:@BARRY_MINOR@:0

# Disable the default -I. -I$(srcdir) -I$(topdir), etc, but $(top_builddir) is
# needed for config.h
DEFAULT_INCLUDES = -I$(top_builddir)
#INCLUDES = $(USB_LIBRARY_CFLAGS) $(OPENSSL_CFLAGS)
INCLUDES = $(USB_LIBRARY_CFLAGS)
#AM_CXXFLAGS = -ansi -Wall -fno-strict-aliasing -g -D__DEBUG_MODE__
AM_CFLAGS = -Wall -fno-strict-aliasing -g -D__BARRY_LIBRARY_BUILD__
AM_CXXFLAGS = -Wall -fno-strict-aliasing -g -D__BARRY_LIBRARY_BUILD__
AM_LDFLAGS =
if WITH_GCCVISIBILITY
AM_CFLAGS += -D__BARRY_HAVE_GCCVISIBILITY__ -fvisibility=hidden
#AM_CXXFLAGS += -D__BARRY_HAVE_GCCVISIBILITY__ -fvisibility=hidden -fvisibility-inlines-hidden
AM_CXXFLAGS += -D__BARRY_HAVE_GCCVISIBILITY__ -fvisibility=hidden
#AM_LDFLAGS += -fvisibility=hidden -fvisibility-inlines-hidden
AM_LDFLAGS += -fvisibility=hidden
endif
include_barrydir = ${includedir}/barry@BARRY_MAJOR@/barry

##
## Boost library usage - required for serialization support, but optional
##
#BOOSTFLAG = -D__BARRY_BOOST_MODE__ -I../../../../boost/rootdir/include/boost-1_33_1
#LDBOOST = ../../../../boost/rootdir/lib/libboost_serialization-gcc-mt-1_33_1.a
##BOOSTFLAG =
##LDBOOST =

# Heavy duty C++ warnings
#WARNFLAGS = -ansi -pedantic -Wall -W -Wold-style-cast -Wfloat-equal -Wwrite-strings -Wno-long-long
#WARNFLAGS = -ansi -pedantic -Wall -W -Weffc++ -Woverloaded-virtual -Wold-style-cast -Wfloat-equal -Wwrite-strings -Wno-long-long -Werror

#LDFLAGS = ../../external/rootdir/libusb/lib/libusb.a $(LDBOOST) $(LDDEBUG)

# To use gettext
datadir = @datadir@
localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

#
# libbarry - main USB protocol interface library
# libbarryalx - ALX library
# libbarrydp - '.debug' parser library
# libbarryjdwp - java debug server library
# libbarrysync - utility functions and classes for syncing and vformats
# libbarrybackup - utility classes for reading/writing Barry backup files
#
lib_LTLIBRARIES = libbarry.la libbarrydp.la libbarryjdwp.la
if WITH_SYNC
lib_LTLIBRARIES += libbarrysync.la
endif
if WITH_BACKUP
lib_LTLIBRARIES += libbarrybackup.la
endif
if WITH_ALX
lib_LTLIBRARIES += libbarryalx.la
endif

include_barry_HEADERS = barry.h barrysync.h barrybackup.h barryalx.h \
	dll.h \
	builder.h \
	common.h \
	configfile.h \
	controller.h \
	xmlparser.h \
	a_common.h \
	a_codsection.h \
	a_library.h \
	a_application.h \
	a_osloader.h \
	a_alxparser.h \
	m_mode_base.h \
	m_desktop.h \
	m_raw_channel.h \
	m_desktoptmpl.h \
	m_ipmodem.h \
	m_serial.h \
	m_javaloader.h \
	m_jvmdebug.h \
	data.h \
	error.h \
	ldif.h \
	ldifio.h \
	log.h \
	parser.h \
	pin.h \
	probe.h \
	protocol.h \
	record.h \
	recordtmpl.h \
	modem.h \
	r_recur_base.h \
	r_calendar.h \
	r_calllog.h \
	r_bookmark.h \
	r_contact.h \
	r_cstore.h \
	r_folder.h \
	r_hhagent.h \
	r_memo.h \
	r_message_base.h \
	r_message.h \
	r_pin_message.h \
	r_saved_message.h \
	r_servicebook.h \
	r_sms.h \
	r_task.h \
	r_timezone.h \
	dataqueue.h \
	router.h \
	socket.h \
	time.h \
	threadwrap.h \
	vsmartptr.h \
	version.h \
	pppfilter.h \
	sha1.h \
	iconv.h \
	cod.h \
	bmp.h \
	s11n-boost.h \
	dp_codinfo.h \
	j_manager.h \
	j_server.h \
	vformat.h \
	vbase.h \
	vcard.h \
	vevent.h \
	vjournal.h \
	vtodo.h \
	mimeio.h \
	scoped_lock.h \
	semaphore.h \
	backup.h \
	restore.h \
	pipe.h \
	connector.h \
	trim.h \
	fifoargs.h \
	tzwrapper.h \
	tr1_support.h

noinst_HEADERS = cbarry.h \
	base64.h \
	record-internal.h \
	r_recur_base-int.h \
	bmp-internal.h \
	cod-internal.h \
	controllerpriv.h \
	packet.h \
	protostructs.h \
	debug.h \
	endian.h \
	strnlen.h \
	getpwuid.h \
	platform.h \
	dp_parser.h \
	j_message.h \
	j_jdwp.h \
	tarfile.h \
	usbwrap_libusb.h \
	usbwrap_libusb_1_0.h \
	ios_state.h \
	clog.h

# Include the windows-only and android-only code files here too
EXTRA_DIST = convo.awk \
	legal.txt \
	iconvwin.cc \
	getpwuidandroid.cc \
	configfilewin32.cc

libbarry_la_SOURCES = dll.h \
	builder.h builder.cc \
	parser.h parser.cc \
	time.h time.cc \
	fifoargs.h fifoargs.cc \
	base64.h base64.cc \
	bmp.h bmp-internal.h bmp.cc \
	cod.h cod-internal.h cod.cc \
	data.h data.cc \
	pin.h pin.cc \
	probe.h probe.cc \
	common.h common.cc \
	configfile.h configfile.cc \
	configfileunix.cc \
	error.h error.cc \
	ldif.h ldif.cc \
	ldifio.h ldifio.cc \
	log.h log.cc \
	socket.cc \
	router.cc \
	dataqueue.cc \
	threadwrap.cc \
	protocol.h protostructs.h protocol.cc \
	record.h recordtmpl.h record-internal.h record.cc \
	r_recur_base.h r_recur_base-int.h r_recur_base.cc \
	r_calendar.h r_calendar.cc \
	r_calllog.h r_calllog.cc \
	r_bookmark.h r_bookmark.cc \
	r_command.cc \
	r_contact.h r_contact.cc \
	r_cstore.h r_cstore.cc \
	r_hhagent.h r_hhagent.cc \
	r_dbdb.cc \
	r_folder.h r_folder.cc \
	r_memo.h r_memo.cc \
	r_message_base.h r_message_base.cc \
	r_recordstate.cc \
	r_servicebook.h r_servicebook.cc \
	r_sms.h r_sms.cc \
	r_task.h r_task.cc \
	r_timezone.h r_timezone.cc \
	packet.h packet.cc \
	controller.h controller.cc \
	pipe.h pipe.cc \
	m_mode_base.h m_mode_base.cc \
	m_desktop.h m_desktop.cc \
	m_raw_channel.h m_raw_channel.cc \
	m_ipmodem.h m_ipmodem.cc \
	m_serial.h m_serial.cc \
	m_javaloader.h m_javaloader.cc \
	m_jvmdebug.h m_jvmdebug.cc \
	connector.h connector.cc \
	version.h version.cc \
	pppfilter.h pppfilter.cc \
	sha1.h sha1.cc \
	iconv.h iconv.cc

# Now sort out USB files
if USE_BARRY_SOCKETS
include_barry_HEADERS += usbwrap.h

libbarry_la_SOURCES += usbwrap.cc

if USE_LIBUSB_0_1
libbarry_la_SOURCES += usbwrap_libusb.cc
endif

if USE_LIBUSB_1_0
libbarry_la_SOURCES += usbwrap_libusb_1_0.cc
endif

endif # USE_BARRY_SOCKETS

#libbarry_la_LIBADD = $(LTLIBOBJS) $(USB_LIBRARY_LIBS) $(OPENSSL_LIBS)
libbarry_la_LIBADD = $(LTLIBOBJS) $(USB_LIBRARY_LIBS) $(ZLIB_LIBS) @LTLIBICONV@ \
	 $(NETWORK_LIBRARY_LIBS)
libbarry_la_LDFLAGS = -version-info ${LIB_BARRY_VERSION}

libbarrydp_la_SOURCES = \
	dp_parser.h dp_parser.cc \
	dp_codinfo.h dp_codinfo.cc
libbarrydp_la_LIBADD = libbarry.la
libbarrydp_la_LDFLAGS = -version-info ${LIB_BARRY_VERSION}

libbarryjdwp_la_SOURCES = \
	j_record.cc \
	j_jdwp.h j_jdwp.cc \
	j_message.h j_message.cc \
	j_server.h j_server.cc \
	j_manager.h j_manager.cc
libbarryjdwp_la_LIBADD = libbarry.la libbarrydp.la $(USB_LIBRARY_LIBS) $(NETWORK_LIBRARY_LIBS)
libbarryjdwp_la_LDFLAGS = -version-info ${LIB_BARRY_VERSION}

if WITH_SYNC
libbarrysync_la_SOURCES = \
	vformat.h vformat.c \
	vbase.h vbase.cc \
	vcard.h vcard.cc \
	vevent.h vevent.cc \
	vjournal.h vjournal.cc \
	vtodo.h vtodo.cc \
	mimeio.h mimeio.cc \
	tzwrapper.h tzwrapper.cc
# if we set CFLAGS and CXXFLAGS ourselves, we need to include
# AM_*FLAGS as well... this only seems to matter for compile flags,
# not link flags
libbarrysync_la_CFLAGS = $(AM_CFLAGS) $(GLIB2_CFLAGS)
libbarrysync_la_CXXFLAGS = $(AM_CXXFLAGS) $(GLIB2_CFLAGS)
libbarrysync_la_LIBADD = libbarry.la $(GLIB2_LIBS)
libbarrysync_la_LDFLAGS = -version-info ${LIB_BARRY_VERSION}
endif

if WITH_BACKUP
libbarrybackup_la_SOURCES = \
	tarfile.cc tarfile-ops-nt.cc \
	backup.h backup.cc \
	restore.h restore.cc
libbarrybackup_la_CFLAGS = $(AM_CFLAGS) $(LIBTAR_CFLAGS) $(LIBZ_CFLAGS)
libbarrybackup_la_CXXFLAGS = $(AM_CXXFLAGS) $(LIBTAR_CFLAGS) $(LIBZ_CFLAGS)
libbarrybackup_la_LIBADD = libbarry.la $(LIBTAR_LIBS) $(LIBZ_LIBS)
libbarrybackup_la_LDFLAGS = -version-info ${LIB_BARRY_VERSION}
endif

if WITH_ALX
libbarryalx_la_SOURCES = \
	xmlparser.h xmlparser.cc \
	a_common.h \
	a_codsection.h a_codsection.cc \
	a_library.h a_library.cc \
	a_application.h a_application.cc \
	a_osloader.h a_osloader.cc \
	a_alxparser.h a_alxparser.cc
libbarryalx_la_CXXFLAGS = $(AM_CXXFLAGS) $(LIBXMLXX_CFLAGS)
libbarryalx_la_LIBADD = libbarry.la $(LIBXMLXX_LIBS)
libbarryalx_la_LDFLAGS = -version-info ${LIB_BARRY_VERSION}
endif

##if DO_TEST
##	bin_PROGRAMS += test-base64 test-data test-time
##
##	test_base64_SOURCES = base64.h base64.cc
##	test_data_SOURCES = data.h data.cc
##	test_time_SOURCES = time.h time.cc
##endif

