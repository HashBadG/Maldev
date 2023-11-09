# Yarnham Makefile

# Compiler
CC = cl.exe

# Compiler flags
CFLAGS = /nologo /Wall /EHsc 

# Source files
SRC = target-1.c target-2.c

# Object files
OBJS = $(SRC:.c=.obj)

# Executables
EXEC_MALICIOUS = target-1.exe target-2.exe

# Malicious target
victim: $(EXEC_MALICIOUS)

# Target for building the malicious executables
%.exe: %.obj
	$(CC) $(CFLAGS) /Fe:$@ $<

# Target for compiling individual source files
%.obj: %.c
	$(CC) $(CFLAGS) /c $<

# Clean target
clean:
	@echo Cleaning directory
	@$(RM) $(EXEC_MALICIOUS) $(OBJS)