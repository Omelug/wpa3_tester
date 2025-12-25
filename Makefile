BUILD_DIR := build
TARGET := wpa3_tester
GRC_CONF := ./debug/grc/wpa3_tester.grc

all: run

.PHONY: all compile run clean_build



install:
	sudo apt install grc

compile:
	@mkdir -p $(BUILD_DIR)
	@
	cmake -S wpa3_test -B $(BUILD_DIR) -Wno-dev
	cmake --build $(BUILD_DIR) --parallel 8

run: compile
	mkdir -p data
	mkdir -p data/wpa3_test/run
	grc -e -c $(GRC_CONF) ./$(BUILD_DIR)/bin/$(TARGET) --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml

# ------- clean ------------------
clean_build:
	rm -rf $(BUILD_DIR)

