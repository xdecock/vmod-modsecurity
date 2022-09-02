AM_CFLAGS = $(VARNISHAPI_CFLAGS) $(MODSECURITY_CFLAGS)

# Modules

vmod_LTLIBRARIES = \
	libvmod_sec.la

libvmod_sec_la_LDFLAGS = $(VMOD_LDFLAGS) -lmodsecurity
libvmod_sec_la_SOURCES = vmod_sec.c
nodist_libvmod_sec_la_SOURCES = \
	vcc_sec_if.c \
	vcc_sec_if.h

@BUILD_VMOD_SEC@

# Test suite

AM_TESTS_ENVIRONMENT = \
	PATH="$(abs_builddir):$(VARNISH_TEST_PATH):$(PATH)" \
	LD_LIBRARY_PATH="$(VARNISH_LIBRARY_PATH):$(MODSECURITY_LIBRARY_PATH)"
TEST_EXTENSIONS = .vtc
VTC_LOG_COMPILER = varnishtest -v
AM_VTC_LOG_FLAGS = \
	-p vcl_path="$(abs_top_srcdir)/vcl:$(VARNISHAPI_VCLDIR)" \
	-p vmod_path="$(abs_builddir)/.libs:$(vmoddir):$(VARNISHAPI_VMODDIR)"

TESTS = \
	vtc/vmod_sec_version.vtc \
	vtc/vmod_sec_load_remote_rule.vtc

# Documentation

dist_doc_DATA = \
	vmod_sec.vcc \
	$(TESTS)

dist_man_MANS = \
	vmod_sec.3


.rst.1:
	$(AM_V_GEN) $(RST2MAN) $< $@
