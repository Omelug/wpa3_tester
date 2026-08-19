.PHONY: debug_netcat

# Streams kernel dmesg over UDP to this host via netconsole.
# Ethernet survives most Wi-Fi driver panics — last kernel words arrive even when dead.
# UART (GPIO14/15) and pstore are baked in by customize.sh — no make target needed.

debug_netcat:
	@test -n "$(PI)" || { echo "Error: PI not set. Usage: make debug_netcat PI=<addr>"; exit 1; }
	@test -n "$(PI_IFACE)" || { echo "Error: cannot detect Pi interface (is PI_IP=$(PI_IP) reachable?)"; exit 1; }
	@HOST_MAC=$$(ip link show $(PI_IFACE) | awk '/ether/{print $$2}') && \
	    test -n "$$HOST_MAC" || { echo "Error: cannot read MAC of $(PI_IFACE)"; exit 1; } && \
	    echo "==> netconsole: Pi $(PI_IP)/eth0 -> $(HOST_IP):$(NETCAT_PORT)  host-MAC $$HOST_MAC" && \
	    $(SSH) "sudo modprobe netconsole netconsole=$(NETCAT_PORT)@$(PI_IP)/eth0,$(NETCAT_PORT)@$(HOST_IP)/$$HOST_MAC"
	@echo "==> Listening on UDP :$(NETCAT_PORT)  (Ctrl+C to stop)"
	nc -u -l -p $(NETCAT_PORT)
