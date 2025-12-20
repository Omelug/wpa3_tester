BUILD_DIR := build
TARGET := wpa3_tester
GRC_CONF := ./debug/grc/wpa3_tester.grc

PHONY: all compile run clean clean-install clean-all

all: compile

install:
	sudo apt install grc

compile:
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f $(BUILD_DIR)/CMakeCache.txt ]; then \
		cd $(BUILD_DIR) && cmake ../wpa3_test; \
	fi
	cmake --build $(BUILD_DIR) --parallel 8

run: all
	mkdir -p data
	grc -e -c $(GRC_CONF) ./$(BUILD_DIR)/bin/$(TARGET) --config wpa3_test/attack_config/DoS_soft/channel_switch.yaml

# ------- clean ------------------
clean:
	rm -rf $(BUILDDIR)

clean-install:
	rm -rf ./lib/external

clean-all: clean clean-install
