AM_CFLAGS = @WARN_CFLAGS@ @XORG_CFLAGS@ @XMODES_CFLAGS@ @PCIACCESS_CFLAGS@ \
	-DREG_DUMPER

noinst_PROGRAMS = bios_reader  $(BIOS_DUMPER) $(SWF_DUMPER)

if LIBPCIACCESS
BIOS_DUMPER = bios_dumper

bios_dumper_SOURCES = bios_dumper.c

bios_dumper_LDADD = $(PCIACCESS_LIBS)

SWF_DUMPER = swf_dumper

swf_dumper_SOURCES = swf_dumper.c

swf_dumper_LDADD = $(PCIACCESS_LIBS)

endif
