# Yarnham Makefile

# Compiler
CC = cl.exe

# Compiler flags
CFLAGS = /nologo /Wall /EHsc 

# Source files
SRC = yarnham.c

# Object files
OBJS = $(SRC:.c=.obj)

# Executables
EXEC_MALICIOUS = yarnham.exe

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
	@$(RM) $(EXEC_MALICIOUS) $(OBJS)