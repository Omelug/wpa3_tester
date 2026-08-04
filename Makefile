BUILD_DIR := build
BUILD_DIR_DEBUG := build/debug
BUILD_DIR_RELEASE := build/release
BUILD_DIR_COVERAGE := build/coverage
BUILD_DIR_ASAN := build/asan
TARGET := wpa3_tester
SOURCE_DIR := .
NPROC := $(shell echo $$(( $(shell nproc) / 2 )))

all: compile
.PHONY: all compile compile_debug compile_release run run_debug run_release clean_build asan_build asan tester_setup

tester_setup:
	@echo "Disabling ath9k_hw ANI for driver stability..."
	echo "options ath9k_hw ani_enable=0" | sudo tee /etc/modprobe.d/ath9k.conf > /dev/null
	@echo " Disabling USB autosuspend..."
	echo "options usbcore autosuspend=-1" | sudo tee /etc/modprobe.d/usbcore.conf > /dev/null
	sudo update-initramfs -u
	@echo "Done. Reboot recommended."

compile:
	@mkdir -p $(BUILD_DIR)
	@if [ ! -f $(BUILD_DIR)/build.ninja ] && [ ! -f $(BUILD_DIR)/Makefile ]; then \
		cmake -S $(SOURCE_DIR) -B $(BUILD_DIR) -G Ninja \
			-DCMAKE_BUILD_TYPE=Debug; \
	fi
	cmake --build $(BUILD_DIR) --target $(TARGET) -j $(NPROC)

compile_release:
	@mkdir -p $(BUILD_DIR_RELEASE)
	@if [ ! -f $(BUILD_DIR_RELEASE)/build.ninja ] && [ ! -f $(BUILD_DIR_RELEASE)/Makefile ]; then \
		cmake -S $(SOURCE_DIR) -B $(BUILD_DIR_RELEASE) -G Ninja \
			-DCMAKE_BUILD_TYPE=Release; \
	fi
	cmake --build $(BUILD_DIR_RELEASE) --target $(TARGET) -j $(NPROC)

run: compile
	mkdir -p data
	mkdir -p data/wpa3_test
	sudo ./$(BUILD_DIR)/bin/$(TARGET) --test_suite CSA_rogueAP_internal_filler

run_release: compile_release
	mkdir -p data
	mkdir -p data/wpa3_test
	sudo ./$(BUILD_DIR_RELEASE)/bin/$(TARGET) --test_suite CSA_rogueAP_internal_filler
	#--config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml

help: compile
	@echo "binary of tester is ./$(BUILD_DIR_RELEASE)/bin/$(TARGET)"
	@sudo ./$(BUILD_DIR)/bin/$(TARGET) --help

# debug visualization
RUN_CALLGRAPH := doc/callgraph/callgraph.out
MY_CODE_FILTER = wpa3_test|main|hw_capabilities|requirement
callgraph:
	@echo "--- Run valgrind ---"
	mkdir -p doc/callgraph
	#FIXME HARDCODED CONFIG
	sudo valgrind --tool=callgrind --callgrind-out-file=$(RUN_CALLGRAPH)  --dump-line=yes ./$(BUILD_DIR)/bin/$(TARGET) --test CSA_ex
	sudo chmod 666 $(RUN_CALLGRAPH)
	sudo chown -R $(USER):$(USER) doc/

graphviz:
	@echo "--- Generating png ---"
	mkdir -p doc/callgraph
	sudo chown $(USER):$(USER) doc/callgraph/callgraph.out
	gprof2dot -f callgrind doc/callgraph/callgraph.out -n0 -w -s > ./doc/callgraph/unfiltered.dot
 	#pozor na -n (limit zobrazení)
 	# --node-label=self-time
	gprof2dot -f callgrind doc/callgraph/callgraph.out -n0.01 -s | \
		grep -E 'digraph|nl80211|graph \[|node \[|(wpa3_tester::|main ->).*(wpa3_tester::|-> main)|nl80211|}$$' | \
		cat \
		> ./doc/callgraph/callgraph.dot
	cat ./doc/callgraph/callgraph.dot | dot -Tsvg -o ./doc/callgraph/callgraph.svg
	@echo "--- Saved to callgraph.svg ---"

# test
test_build:
	cmake --build $(BUILD_DIR) -j $(shell nproc --ignore=2)

test: test_build
	sudo -E ctest --test-dir $(BUILD_DIR) --output-on-failure

test_manual_build:
	cmake --build $(BUILD_DIR) --target \
		test_list_external_entities \
		test_info_openwrt \
		test_manual_channel_switch \
		test_manual_get_commit_values \
		test_manual_mc_mitm \
		test_manual_iface \
		test_manual_injection_two_iface \
		test_config_validation \
		-j $(NPROC)

config_validation:
	cmake --build $(BUILD_DIR) --target test_config_validation -j $(NPROC)
	$(BUILD_DIR)/bin/manual_tests/config/test_config_validation

# coverage
coverage_build:
	mkdir -p $(BUILD_DIR_COVERAGE)
	@if [ ! -f $(BUILD_DIR_COVERAGE)/build.ninja ] && [ ! -f $(BUILD_DIR_COVERAGE)/Makefile ]; then \
        cmake -S $(SOURCE_DIR) -B $(BUILD_DIR_COVERAGE) -G Ninja \
        	-DENABLE_COVERAGE=ON \
        	-DCMAKE_C_COMPILER_LAUNCHER=ccache \
        	-DCMAKE_CXX_COMPILER_LAUNCHER=ccache; \
    fi
	cmake --build $(BUILD_DIR_COVERAGE) -j $(NPROC)

coverage: coverage_build
	cmake --build $(BUILD_DIR_COVERAGE) --target coverage

asan_build:
	mkdir -p $(BUILD_DIR_ASAN)
	@if [ ! -f $(BUILD_DIR_ASAN)/build.ninja ] && [ ! -f $(BUILD_DIR_ASAN)/Makefile ]; then \
		cmake -S $(SOURCE_DIR) -B $(BUILD_DIR_ASAN) -G Ninja \
			-DENABLE_ASAN=ON \
			-DCMAKE_BUILD_TYPE=Debug \
			-DCMAKE_C_COMPILER_LAUNCHER=ccache \
			-DCMAKE_CXX_COMPILER_LAUNCHER=ccache; \
	fi
	cmake --build $(BUILD_DIR_ASAN) -j $(NPROC)

asan: asan_build
	cmake --build $(BUILD_DIR_ASAN) --target leak-check

# overview
build_overview:
	cmake --build $(BUILD_DIR) --target result_overview -j $(NPROC)

make_overview: build_overview
	./$(BUILD_DIR)/bin/result_overview

# clear
clean_build:
	rm -rf $(BUILD_DIR) $(BUILD_DIR_RELEASE)
clear_cache:
	rm -rf ./data/cache