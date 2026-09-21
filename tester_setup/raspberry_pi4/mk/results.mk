RESULTS_DATA    := $(CURDIR)/run/data
RESULTS_HTML    := $(CURDIR)/run/html
RESULT_OVERVIEW := $(SRC_ROOT)/build/bin/result_overview

.PHONY: results results_gen_only

# syncs test data from Pi and generate result overview
# output:  run/data/  - mirror of Pi's ~/wpa3_tester/data/
#          run/html/  - generated HTML site

results:
	@test -n "$(PI)" || { echo "Error: PI not set. Usage: make results PI=<address>"; exit 1; }
	$(MAKE) -C $(SRC_ROOT) build_overview
	mkdir -p $(RESULTS_DATA)
	$(RSYNC) -az --delete --info=progress2 \
		$(PI_USER)@$(PI):$(REMOTE_ABS)/data/ \
		$(RESULTS_DATA)/
	$(MAKE) results_gen_only

results_gen_only_force:
	rm -rf $(RESULTS_HTML)
	$(MAKE) results

results_gen_only:
	$(MAKE) -C $(SRC_ROOT) build_overview
	#rm -rf $(RESULTS_HTML)
	$(RESULT_OVERVIEW) \
		--data_dir   $(RESULTS_DATA) \
		--output_dir $(RESULTS_HTML)
	@echo "==> Results generated: $(RESULTS_HTML)/index.html"
