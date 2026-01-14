# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -O2 -Wall -Wextra -Iinclude
LDFLAGS = -static-libgcc -static-libstdc++

# Directories
SRC_DIR = src
INC_DIR = include
BIN_DIR = bin

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.cpp)
OBJS = $(SRCS:.cpp=.o)

# Target executable
TARGET = $(BIN_DIR)/scanner

# Rules
.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BIN_DIR)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(SRC_DIR)/*.o
	rm -f $(TARGET)

install: $(TARGET)
	@echo "Installing mem_scanner to /opt/tracex/bin/..."
	@mkdir -p /opt/tracex/bin
	@cp $(TARGET) /opt/tracex/bin/mem_scanner
	@chmod +x /opt/tracex/bin/mem_scanner
	@# Optional: Set capability to allow PTRACE without full root
	@# setcap cap_sys_ptrace+ep /opt/tracex/bin/mem_scanner
