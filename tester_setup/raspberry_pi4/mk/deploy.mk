TEST_SUITE ?= mc_mitm_filler

# forward-declare targets from sibling mk files so CLion resolves them
.PHONY: bootstrap run run_debug deploy-debug deploy-cross internet gdbserver-start

bootstrap:
	@test -n "$(PI)" || { echo "Error: PI is not set. Usage: make bootstrap PI=<address>"; exit 1; }
	scp image/drivers.sh $(PI_USER)@$(PI):/tmp/wpa3-drivers.sh
	scp bootstrap.sh $(PI_USER)@$(PI):/tmp/bootstrap.sh
	$(SSH) "chmod +x /tmp/bootstrap.sh && /tmp/bootstrap.sh"

run: deploy-cross internet
	$(SSH) -t "sudo $(REMOTE)/build/bin/wpa3_tester --test_suite $(TEST_SUITE)"

FORCE:

## DISCLAIMER -- Clion dont work with newest gdb,
# I setup it with: (same as raspberry)
#~ % gdb-multiarch --version
#     GNU gdb (Debian 16.3-1) 16.3
run_debug:  deploy-cross internet FORCE
	$(SSH) "sudo pkill gdbserver 2>/dev/null || true"
	@echo "==> gdbserver listening on $(PI):$(GDB_PORT)"
	@echo "    Connect with:"
	@echo "      gdb-multiarch $(CROSS_BUILD)/bin/wpa3_tester"
	@echo "      (gdb) target remote $(PI):$(GDB_PORT)"
	$(SSH) -t "sudo gdbserver :$(GDB_PORT) $(REMOTE)/build/bin/wpa3_tester --test_suite $(TEST_SUITE)"
	@echo "==> gdbserver running on $(PI):$(GDB_PORT)"
