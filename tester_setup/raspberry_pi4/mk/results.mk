RESULTS_DATA    := $(CURDIR)/run/data
RESULTS_HTML    := $(CURDIR)/run/html
RESULT_OVERVIEW := $(SRC_ROOT)/build/bin/result_overview

.PHONY: results results_gen_only

# Syncs test data from Pi (mirrors exactly) then generates the HTML result overview.
# Output:  run/data/  — mirror of Pi's ~/wpa3_tester/data/
#          run/html/  — generated HTML site

results:
	@test -n "$(PI)" || { echo "Error: PI not set. Usage: make results PI=<address>"; exit 1; }
	$(MAKE) -C $(SRC_ROOT) build_overview
	mkdir -p $(RESULTS_DATA)
	rsync -az --delete --info=progress2 \
		$(PI_USER)@$(PI):$(REMOTE_ABS)/data/ \
		$(RESULTS_DATA)/
	$(MAKE) results_gen_only

results_gen_only:
	rm -rf $(RESULTS_HTML)
	$(RESULT_OVERVIEW) \
		--data_dir   $(RESULTS_DATA) \
		--output_dir $(RESULTS_HTML)
	@echo "==> Results generated: $(RESULTS_HTML)/index.html"
