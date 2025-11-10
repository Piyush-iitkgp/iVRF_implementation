# =========================
#   iVRF Project Makefile
# =========================

# Compilers
CXX = g++
CC  = gcc

# Flags
CXXFLAGS = -O2 -Wall -I./falcon_local -march=native -maes
CFLAGS   = -O2 -Wall -I./falcon_local -march=native -maes
LDFLAGS  = -L/usr/lib/x86_64-linux-gnu

# Folders
SRC_CPP = ivrf.cpp main.cpp
# Exclude test/benchmark files with their own main() functions
SRC_C   = $(filter-out falcon_local/ivrf.c falcon_local/speed.c falcon_local/test_falcon.c, $(wildcard falcon_local/*.c))
BUILD_DIR = build

# Object files (placed in build/)
OBJ_CPP = $(patsubst %.cpp, $(BUILD_DIR)/%.o, $(SRC_CPP))
OBJ_C   = $(patsubst %.c, $(BUILD_DIR)/%.o, $(SRC_C))
OBJ = $(OBJ_CPP) $(OBJ_C)

# Output binary
TARGET = $(BUILD_DIR)/ivrf_demo

# =========================
#         Rules
# =========================
all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/falcon_local

$(TARGET): $(BUILD_DIR) $(OBJ)
	$(CXX) $(OBJ) -o $(TARGET) $(LDFLAGS) -lcrypto -lssl

# Compile C++ sources
$(BUILD_DIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Compile C sources
$(BUILD_DIR)/%.o: %.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
