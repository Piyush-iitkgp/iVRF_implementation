# =========================
#   iVRF Project Makefile
# =========================

CXX = g++
CC  = gcc
CXXFLAGS = -O2 -Wall -I./falcon_local -march=native -maes
CFLAGS   = -O2 -Wall -I./falcon_local -march=native -maes
LDFLAGS  = -L/usr/lib/x86_64-linux-gnu -lcrypto -lssl

BUILD_DIR = build

# C++ sources
CPP_OBJS = $(BUILD_DIR)/ivrf.o $(BUILD_DIR)/main.o

# C sources (Falcon + DRBG)
C_OBJS = \
	$(BUILD_DIR)/falcon_local/codec.o \
	$(BUILD_DIR)/falcon_local/common.o \
	$(BUILD_DIR)/falcon_local/drbg_rng.o \
	$(BUILD_DIR)/falcon_local/falcon.o \
	$(BUILD_DIR)/falcon_local/fft.o \
	$(BUILD_DIR)/falcon_local/fpr.o \
	$(BUILD_DIR)/falcon_local/keygen.o \
	$(BUILD_DIR)/falcon_local/rng.o \
	$(BUILD_DIR)/falcon_local/shake.o \
	$(BUILD_DIR)/falcon_local/sign.o \
	$(BUILD_DIR)/falcon_local/vrfy.o

TARGET = $(BUILD_DIR)/exec

all: $(TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/falcon_local

$(TARGET): $(BUILD_DIR) $(CPP_OBJS) $(C_OBJS)
	$(CXX) $(CPP_OBJS) $(C_OBJS) -o $(TARGET) $(LDFLAGS)

$(BUILD_DIR)/%.o: %.cpp
	mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD_DIR)/falcon_local/%.o: falcon_local/%.c
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
