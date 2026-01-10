BUILD_DIR := build
TARGET := wpa3_tester
GRC_CONF := ./debug/grc/wpa3_tester.grc

all: run

.PHONY: all compile run clean_build


clion_debug: compile
	sudo ./build/bin/wpa3_tester --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml

install:
	sudo apt install grc

compile:
	@mkdir -p $(BUILD_DIR)
	cmake --build ./build
	cmake --build ./build --target wpa3_tester -j 6

run: compile
	mkdir -p data
	mkdir -p data/wpa3_test/run
	grc -e -c $(GRC_CONF) sudo ./$(BUILD_DIR)/bin/$(TARGET) --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml

# ------- clean ------------------
clean_build:
	rm -rf $(BUILD_DIR)

RUN_CALLGRAPH := doc/callgraph/callgraph.out
MY_CODE_FILTER = wpa3_test|main|hw_capabilities|requirement
callgraph:
	@echo "--- Run valgrind ---"
	mkdir -p doc/callgraph
	sudo valgrind --tool=callgrind --callgrind-out-file=$(RUN_CALLGRAPH)  --dump-line=yes ./$(BUILD_DIR)/bin/$(TARGET) --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml
	sudo chmod 666 $(RUN_CALLGRAPH)
	sudo chown -R $(USER):$(USER) doc/
graphviz:
	@echo "--- Generating png ---"
	mkdir -p doc/callgraph
	sudo chown $(USER):$(USER) doc/callgraph/callgraph.out
	gprof2dot -f callgrind doc/callgraph/callgraph.out -n0 -w -s > ./doc/callgraph/unfiltered.dot
 	#TODO pozor na -n (limit zobrazení)
 	# --node-label=self-time
	gprof2dot -f callgrind doc/callgraph/callgraph.out -n0.01 -s | \
		#grep -vE '(void|auto|char&) std::|\(anonymous namespace\)::|0x[0-9a-fA-F]+|nlohmann::|Tins::|libc.so|libgcc|libnl|__|_dl_|_[A-Za-z0-9]{32}|_[A-Za-z0-9]{64}|Id-linux|YAML::|(int|bool|long) YAML::|operator|lib{3,8}.so|argparse' | \
		grep -E 'digraph|nl80211|graph \[|node \[|(wpa3_tester::|main ->).*(wpa3_tester::|-> main)|nl80211|}$$' | \
		grep -vE 'std::' \
		> ./doc/callgraph/callgraph.dot
	cat ./doc/callgraph/callgraph.dot | dot -Tsvg -o ./doc/callgraph/callgraph.svg
	@echo "--- Saved to callgraph.svg ---"