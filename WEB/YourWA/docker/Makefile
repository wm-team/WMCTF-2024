ifeq ($(OS), Windows_NT)
    PLATFORM := Windows
    MKFLAG_EXE := mkflag.exe
    RMFLAG_EXE := rmflag.exe
    MKFLAG_SRC := mkflag.c
    RMFLAG_SRC := rmflag.c
    CC := gcc
    CFLAGS := -ladvapi32
    MKFLAG_MANIFEST := mkflag.manifest
    RMFLAG_MANIFEST := rmflag.manifest
    MKFLAG_RCFILE := mkflag.rc
    RMFLAG_RCFILE := rmflag.rc
    MKFLAG_RESFILE := mkflag.res
    RMFLAG_RESFILE := rmflag.res
else
    PLATFORM := Unix
    MKFLAG_EXE := mkflag
    RMFLAG_EXE := rmflag
    MKFLAG_SRC := mkflag.c
    RMFLAG_SRC := rmflag.c
    CC := gcc
    CFLAGS :=
endif

# Targets
all: $(MKFLAG_EXE) $(RMFLAG_EXE)

# Unix targets
mkflag: mkflag.c
	$(CC) $(MKFLAG_SRC) -o $(MKFLAG_EXE) $(CFLAGS)
	@echo "# Compiled mkflag for Unix/Linux"
	if [ -x /usr/bin/sudo ]; then \
		sudo chown root:root $(MKFLAG_EXE) ;\
		sudo chmod u+s $(MKFLAG_EXE) ;\
		echo "# The mkflag executable now has the root setuid bit" ;\
	fi

rmflag: rmflag.c
	$(CC) $(RMFLAG_SRC) -o $(RMFLAG_EXE) $(CFLAGS)
	@echo "# Compiled rmflag for Unix/Linux"
	if [ -x /usr/bin/sudo ]; then \
		sudo chown root:root $(RMFLAG_EXE) ;\
		sudo chmod u+s $(RMFLAG_EXE) ;\
		echo "# The rmflag executable now has the root setuid bit" ;\
	fi

# Windows targets
mkflag.exe: mkflag.c
	@echo "# Creating resource file for manifest..."
	echo "1 24 \"$(MKFLAG_MANIFEST)\"" > $(MKFLAG_RCFILE)
	windres $(MKFLAG_RCFILE) -O coff -o $(MKFLAG_RESFILE)
	$(CC) $(MKFLAG_SRC) $(MKFLAG_RESFILE) -o $(MKFLAG_EXE) $(CFLAGS)
	@echo "# Compiled mkflag for Windows"
	@echo "# The executable will request administrative privileges on run"

rmflag.exe: rmflag.c
	@echo "# Creating resource file for manifest..."
	echo "1 24 \"$(RMFLAG_MANIFEST)\"" > $(RMFLAG_RCFILE)
	windres $(RMFLAG_RCFILE) -O coff -o $(RMFLAG_RESFILE)
	$(CC) $(RMFLAG_SRC) $(RMFLAG_RESFILE) -o $(RMFLAG_EXE) $(CFLAGS)
	@echo "# Compiled rmflag for Windows"
	@echo "# The executable will request administrative privileges on run"

# Clean up
clean:
	rm -f mkflag mkflag.exe rmflag rmflag.exe $(MKFLAG_RCFILE) $(MKFLAG_RESFILE) $(RMFLAG_RCFILE) $(RMFLAG_RESFILE)

compile: $(MKFLAG_EXE) $(RMFLAG_EXE)
	rm -f $(MKFLAG_RCFILE) $(MKFLAG_RESFILE) $(RMFLAG_RCFILE) $(RMFLAG_RESFILE)

.PHONY: all clean compile
