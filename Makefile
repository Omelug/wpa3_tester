CXX      := g++
CXXFLAGS := -std=c++20 -g -O0 -Wall -Wextra -MMD -MP
TARGET   := wpa3_tester

SRC_DIRS := . wpa3_test/src wpa3_test_suite/src
INC_DIRS := -Iinclude -Iwpa3_test/include -Ilib/external -Ilib/external/argparse/include -Ilib/external/json-schema-validator/src -Ilib/external/json-schema-validator/include

BUILDDIR := build_make

LDFLAGS  := -L/usr/lib
LDLIBS   := -lyaml-cpp
SRCS := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/**/*.cpp) $(wildcard $(dir)/*.cpp))

OBJS := $(patsubst %.cpp,$(BUILDDIR)/%.o,$(SRCS))
DEPS := $(OBJS:.o=.d)

.PHONY: all clean clean-install clean-all run install deps

all: $(BUILDDIR)/$(TARGET)

$(BUILDDIR)/$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

$(BUILDDIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) $(INC_DIRS) -c $< -o $@

-include $(DEPS)

run: all
	mkdir -p data
	./$(BUILDDIR)/$(TARGET)

install: deps
	@echo "✓ All dependencies installed successfully"

deps:
	@echo "Installing system packages (Debian-based)..."
	sudo apt install -y libyaml-cpp-dev wget git nlohmann-json3-dev
	@echo "Installing C++ argparse (header-only) into lib/external..."
	mkdir -p lib/external
	@if [ ! -d lib/external/argparse ]; then \
		echo "Cloning p-ranav/argparse..."; \
		cd lib/external && git clone -q https://github.com/p-ranav/argparse.git; \
		echo "[OK] argparse cloned"; \
	else \
		echo "[OK] argparse already exists"; \
	fi
	@echo "Setting up header-only libraries..."
	mkdir -p lib/external
	@if [ ! -f lib/external/json.hpp ]; then \
		echo "Downloading nlohmann/json..."; \
		wget -q -O lib/external/json.hpp https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp; \
		echo "[OK] nlohmann/json downloaded"; \
	else \
		echo "[OK] nlohmann/json already exists"; \
	fi
	@if [ ! -d lib/external/json-schema-validator ]; then \
		echo "Cloning json-schema-validator (JSON Schema validator for nlohmann/json)..."; \
		cd lib/external && git clone -q https://github.com/pboettch/json-schema-validator.git; \
		echo "[OK] json-schema-validator cloned"; \
	else \
		echo "[OK] json-schema-validator already exists"; \
	fi

# ------- clean ------------------
clean:
	rm -rf $(BUILDDIR)

clean-install:
	rm -rf ./lib/external

clean-all: clean clean-install
