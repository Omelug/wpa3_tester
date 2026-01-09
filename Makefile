BUILD_DIR := build
TARGET := wpa3_tester
GRC_CONF := ./debug/grc/wpa3_tester.grc

all: run

.PHONY: all compile run clean_build


clion_debug:
	cmake --build /home/kali/ClionProjects/wpa3_tester/build --target wpa3_tester -j 6 -DCMAKE_BUILD_TYPE=Debug
	sudo ./build/bin/wpa3_tester --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml

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
	grc -e -c $(GRC_CONF) sudo ./$(BUILD_DIR)/bin/$(TARGET) --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml

# ------- clean ------------------
clean_build:
	rm -rf $(BUILD_DIR)

RUN_CALLGRAPH := doc/callgraph/callgraph.out
MY_CODE_FILTER = wpa3_test|main|hw_capabilities|requirement
callgraph:
	@echo "--- Run valgrind ---"
	mkdir -p doc/callgraph
	sudo valgrind --tool=callgrind --callgrind-out-file=$(RUN_CALLGRAPH)  \
	--dump-line=yes \
	--fn-skip='std::*' \
	  --fn-skip='nlohmann::*' \
      --fn-skip='YAML::*' \
      --fn-skip='boost::*' \
      --fn-skip='*libyaml*' \
      --fn-skip='*libc.so*' \
      --fn-skip='*lib*.so*' \
		./$(BUILD_DIR)/bin/$(TARGET) --config wpa3_test/attack_config/DoS_soft/channel_switch/channel_switch.yaml
	sudo chmod 666 $(RUN_CALLGRAPH)
	sudo chown -R $(USER):$(USER) doc/
graphviz:
	@echo "--- Generating png ---"
	mkdir -p doc/callgraph
	sudo chown $(USER):$(USER) doc/callgraph/callgraph.out
	gprof2dot -f callgrind $(RUN_CALLGRAPH) -n0.1 --depth=5 -s | \
        grep -vE "libc.so.6|_*|YAML::|std::|anonymous|_Destroy|__libc" | \
        grep -vE '\.so|std::|0x[0-9a-f]| \.so\.*' | \
		dot -Tsvg -o ./doc/callgraph/callgraph.svg
	@echo "--- Saved to callgraph.svg ---"