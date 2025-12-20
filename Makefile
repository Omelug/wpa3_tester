BUILD_DIR := build
TARGET := wpa3_tester

PHONY: all compile run clean clean-install clean-all

all: compile
compile:
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f $(BUILD_DIR)/CMakeCache.txt ]; then \
		cd $(BUILD_DIR) && cmake ../wpa3_test; \
	fi
	cmake --build $(BUILD_DIR) --parallel 8

run: all
	mkdir -p data
	./$(BUILD_DIR)/bin/$(TARGET) --config wpa3_test/attack_config/DoS_soft/channel_switch.yaml

# ------- clean ------------------
clean:
	rm -rf $(BUILDDIR)

clean-install:
	rm -rf ./lib/external

clean-all: clean clean-install
