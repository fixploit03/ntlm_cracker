# Makefile for ntlm_cracker.cpp

# Compiler to use
CC = g++

# Compiler flags
CFLAGS = -std=c++17 -O2 -Wall

# Libraries to link
LIBS = -lssl -lcrypto -pthread

# Target executable name
TARGET = ntlm_cracker

# Source file
SOURCE = ntlm_cracker.cpp

# Default target
all: $(TARGET)

# Compile the program
$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)

# Install the program to /usr/local/bin
install: $(TARGET)
	sudo install -m 755 $(TARGET) /usr/local/bin/

# Clean up compiled files
clean:
	rm -f $(TARGET)

# Uninstall the program from /usr/local/bin
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

.PHONY: all install clean uninstall
