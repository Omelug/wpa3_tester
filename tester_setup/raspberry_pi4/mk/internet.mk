.PHONY: internet internet-off

internet:
	@test -n "$(HOST_IFACE)" || { echo "Error: cannot detect host internet interface"; exit 1; }
	@test -n "$(PI_IFACE)"   || { echo "Error: cannot detect Pi interface (is PI_IP reachable?)"; exit 1; }
	@echo "==> Sharing internet: $(HOST_IFACE) -> $(PI_IFACE) (Pi=$(PI_IP))"
	sudo sysctl -w net.ipv4.ip_forward=1
	sudo iptables -t nat -C POSTROUTING -o $(HOST_IFACE) -j MASQUERADE 2>/dev/null || \
	    sudo iptables -t nat -A POSTROUTING -o $(HOST_IFACE) -j MASQUERADE
	sudo iptables -C FORWARD -i $(PI_IFACE) -o $(HOST_IFACE) -j ACCEPT 2>/dev/null || \
	    sudo iptables -A FORWARD -i $(PI_IFACE) -o $(HOST_IFACE) -j ACCEPT
	@echo "==> Done."

internet-off:
	sudo iptables -t nat -D POSTROUTING -o $(HOST_IFACE) -j MASQUERADE 2>/dev/null || true
	sudo iptables -D FORWARD -i $(PI_IFACE) -o $(HOST_IFACE) -j ACCEPT 2>/dev/null || true
	sudo sysctl -w net.ipv4.ip_forward=0
	@echo "==> NAT removed."
