AUTOMAKE_OPTIONS = subdir-objects
bin_PROGRAMS = agency agent
asm_sources = src/agency.asm src/fp_lib.asm
agency_SOURCES = src/encryption_functions.c ${asm_sources}
agent_SOURCES = src/agent.asm
#cs12lib = cs12Lib/cs12Lib.o
cs12lib =
YASMFLAGS = @PACKAGE_YASMFLAGS@
LDFLAGS = @PACKAGE_LDFLAGS@
AM_CPPFLAGS = @PACKAGE_CFLAGS@
YASM = yasm
CLEANFILES = src/*.lst

.asm.o:
	$(YASM) $(DEFS) $(YASMFLAGS) $(ASFLAGS) $< -o $@  -l $(@:.o=.lst)

agency$(EXEEXT): src/agency.o src/fp_lib.o src/encryption_functions.o $(cs12lib)
	gcc $(subst -c,,$(AM_CPPFLAGS)) $(CFLAGS) -o $@ $^ $(LDFLAGS)

agent$(EXEEXT): src/agent.o src/fp_lib.o $(cs12lib)
	gcc $(subst -c,,$(AM_CPPFLAGS)) $(CFLAGS) -o $@ $^ $(LDFLAGS)
