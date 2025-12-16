CXX      := g++
CXXFLAGS := -std=c++20 -g -O0 -Wall -Wextra -Iexternal
LDFLAGS  := -lyaml-cpp
TARGET   := wpa3_tester
SRC      := main.cpp
BUILDDIR := build_make

.PHONY: all clean run install deps

all: $(BUILDDIR)/$(TARGET)

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/$(TARGET): $(SRC) | $(BUILDDIR)
	$(CXX) $(CXXFLAGS) $(SRC) -o $(BUILDDIR)/$(TARGET) $(LDFLAGS)

run: all
	./$(BUILDDIR)/$(TARGET)

install: deps
	@echo "✓ All dependencies installed successfully"

deps:
	@echo "Installing system packages..."
	sudo apt install -y libyaml-cpp-dev wget git
	@echo "Setting up header-only libraries..."
	mkdir -p lib
	mkdir -p lib/external
	@if [ ! -f external/json.hpp ]; then \
		echo "Downloading nlohmann/json..."; \
		wget -q -O lib/external/json.hpp https://raw.githubusercontent.com/nlohmann/json/develop/single_include/nlohmann/json.hpp; \
		echo "[OK] nlohmann/json downloaded"; \
	else \
		echo "[OK] nlohmann/json already exists"; \
	fi
	@if [ ! -d external/json-schema-validator ]; then \
		echo "Cloning json-schema-validator..."; \
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
