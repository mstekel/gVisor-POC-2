#!/bin/bash
# setup-netns.sh <netns-name> <create|destroy>

NETNS=$1
ACTION=$2
VETH_HOST="veth0"
VETH_SANDBOX="veth1"
HOST_IP="10.0.0.1"
SANDBOX_IP="10.0.0.2"
ECHO_PORT=19876

if [ -z "$NETNS" ] || [ -z "$ACTION" ]; then
    echo "Usage: $0 <netns-name> <create|destroy>"
    exit 1
fi

case "$ACTION" in

create)
    #echo "[netns] Creating network namespace: $NETNS"
    ip netns add "$NETNS"

    #echo "[netns] Creating veth pair: $VETH_HOST <-> $VETH_SANDBOX"
    ip link add "$VETH_HOST" type veth peer name "$VETH_SANDBOX"

    #echo "[netns] Moving $VETH_SANDBOX into namespace $NETNS"
    ip link set "$VETH_SANDBOX" netns "$NETNS"

    #echo "[netns] Configuring host side: $VETH_HOST @ $HOST_IP"
    ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    #echo "[netns] Configuring sandbox side: $VETH_SANDBOX @ $SANDBOX_IP"
    ip netns exec "$NETNS" ip addr add "${SANDBOX_IP}/24" dev "$VETH_SANDBOX"
    ip netns exec "$NETNS" ip link set "$VETH_SANDBOX" up
    ip netns exec "$NETNS" ip link set lo up
    ip netns exec "$NETNS" ip route add default via "$HOST_IP"

    #echo "[netns] Adding iptables rules"
    # Allow sandbox -> host echo server. This reaches a *local* host address
    # (10.0.0.1 on veth0), so it hits the INPUT chain, not FORWARD. Insert at the
    # top of INPUT so it wins over a host firewall's default reject (e.g. firewalld
    # on RHEL/Oracle rejects with icmp-host-prohibited -> "No route to host").
    iptables -I INPUT -s "$SANDBOX_IP" -d "$HOST_IP" -p tcp -m tcp --dport "$ECHO_PORT" -j ACCEPT
    # On firewalld hosts the iptables INPUT rule above is NOT enough: firewalld
    # keeps its own nftables table whose reject still fires (an ACCEPT in the
    # iptables-nft table is not final across tables). Put the host veth in
    # firewalld's "trusted" zone so firewalld itself accepts the allowed path.
    # The external block stays enforced by the FORWARD DROP rule below.
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=trusted --add-interface="$VETH_HOST" >/dev/null 2>&1
    fi
    # Allow sandbox -> host echo server
    iptables -I FORWARD -s "$SANDBOX_IP" -d "$HOST_IP" -p tcp -m tcp --dport "$ECHO_PORT" -j ACCEPT
    # Allow established/related back
    iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Drop everything else from sandbox
    iptables -I FORWARD -s "$SANDBOX_IP" ! -d "$HOST_IP" -j DROP
    # Enable forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward

    #echo "[netns] Done. Sandbox can reach $HOST_IP:$ECHO_PORT only."
    #echo "[netns] Namespace path: /var/run/netns/$NETNS"
    ;;

destroy)
    #echo "[netns] Removing iptables rules"
    iptables -D INPUT -s "$SANDBOX_IP" -d "$HOST_IP" -p tcp -m tcp --dport "$ECHO_PORT" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -s "$SANDBOX_IP" -d "$HOST_IP" -p tcp -m tcp --dport "$ECHO_PORT" -j ACCEPT 2>/dev/null
    iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -D FORWARD -s "$SANDBOX_IP" ! -d "$HOST_IP" -j DROP 2>/dev/null

    # Remove the host veth from firewalld's trusted zone (no-op if not added)
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        firewall-cmd --zone=trusted --remove-interface="$VETH_HOST" >/dev/null 2>&1
    fi

    #echo "[netns] Removing veth pair"
    ip link del "$VETH_HOST" 2>/dev/null

    #echo "[netns] Removing network namespace"
    ip netns del "$NETNS" 2>/dev/null

    #echo "[netns] Cleaned up."
    ;;

*)
    #echo "Unknown action: $ACTION"
    exit 1
    ;;
esac