# Yarnham Makefile

# Compiler
CC = cl.exe

# Compiler flags
CFLAGS = /nologo /Wall /EHsc 

# Source files
SRC = yarnham.c target-1.c target-2.c ProcessShellcode-Injector.c

# Object files
OBJS = $(SRC:.c=.obj)

# Executables
EXEC_MALICIOUS = yarnham.exe ProcessShellcode-Injector.exe

# Malicious target
malicious: $(EXEC_MALICIOUS)

# Target for building the malicious executables
%.exe: %.obj
	$(CC) $(CFLAGS) /Fe:$@ $<

# Target for compiling individual source files
%.obj: %.c
	$(CC) $(CFLAGS) /c $<

# Clean target
clean:
	@echo Cleaning directory
	@$(RM) $(EXEC_MALICIOUS)
