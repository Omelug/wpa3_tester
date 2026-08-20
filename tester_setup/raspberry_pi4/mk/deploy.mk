TEST_SUITE ?= CSA_rogueAP_internal_filler

.PHONY: bootstrap deploy run run-debug deploy-debug

bootstrap:
	@test -n "$(PI)" || { echo "Error: PI is not set. Usage: make bootstrap PI=<address>"; exit 1; }
	scp image/drivers.sh $(PI_USER)@$(PI):/tmp/wpa3-drivers.sh
	scp bootstrap.sh $(PI_USER)@$(PI):/tmp/bootstrap.sh
	$(SSH) "chmod +x /tmp/bootstrap.sh && /tmp/bootstrap.sh"

deploy:
	@test -n "$(PI)" || { echo "Error: PI is not set. Usage: make deploy PI=<address>"; exit 1; }
	rsync -az --delete --info=progress2 \
		--exclude='.git/' \
		--exclude='build/' \
		--exclude='data/' \
		--exclude='tools/' \
		$(SRC_ROOT)/ $(PI_USER)@$(PI):$(REMOTE)/
	$(SSH) "make -C $(REMOTE) -j$$(nproc) compile"

run: deploy-cross internet
	$(SSH) -t "sudo $(REMOTE)/build/bin/wpa3_tester --test_suite $(TEST_SUITE)"

deploy-debug: deploy-cross gdbserver-start

run-debug: deploy-debug internet
	@echo "==> gdbserver listening on $(PI):$(GDB_PORT)"
	@echo "    Connect with:"
	@echo "      gdb-multiarch $(CROSS_BUILD)/bin/wpa3_tester"
	@echo "      (gdb) target remote $(PI):$(GDB_PORT)"
	$(SSH) -t "sudo gdbserver :$(GDB_PORT) $(REMOTE)/build/bin/wpa3_tester --test_suite $(TEST_SUITE)"
