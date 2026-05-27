#!/bin/bash
# setup-netns.sh <netns-name> <action>
#
# action=create:  create veth pair, configure namespace, add iptables rules
# action=destroy: tear everything down cleanly
#
# After 'create', the sandbox should be launched with:
#   --network=host (gVisor shares host netns)
#   OCI config: { "type": "network", "path": "/var/run/netns/<netns-name>" }
#
# Host veth address:    10.0.0.1  (reachable from sandbox as the "host")
# Sandbox veth address: 10.0.0.2

NETNS=$1
ACTION=$2
VETH_HOST="veth-host-${NETNS}"
VETH_SANDBOX="veth-sb-${NETNS}"
HOST_IP="10.0.0.1"
SANDBOX_IP="10.0.0.2"
ECHO_PORT=19876

if [ -z "$NETNS" ] || [ -z "$ACTION" ]; then
    echo "Usage: $0 <netns-name> <create|destroy>"
    exit 1
fi

case "$ACTION" in

create)
    echo "[netns] Creating network namespace: $NETNS"
    ip netns add "$NETNS"

    echo "[netns] Creating veth pair: $VETH_HOST <-> $VETH_SANDBOX"
    ip link add "$VETH_HOST"    type veth peer name "$VETH_SANDBOX"

    echo "[netns] Moving $VETH_SANDBOX into namespace $NETNS"
    ip link set "$VETH_SANDBOX" netns "$NETNS"

    echo "[netns] Configuring host side: $VETH_HOST @ $HOST_IP"
    ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
    ip link set "$VETH_HOST" up

    echo "[netns] Configuring sandbox side: $VETH_SANDBOX @ $SANDBOX_IP"
    ip netns exec "$NETNS" ip addr add "${SANDBOX_IP}/24" dev "$VETH_SANDBOX"
    ip netns exec "$NETNS" ip link set "$VETH_SANDBOX" up
    ip netns exec "$NETNS" ip link set lo up
    # Default route: all traffic from sandbox goes via host veth
    ip netns exec "$NETNS" ip route add default via "$HOST_IP"

    echo "[netns] Adding iptables rules"
    # Allow sandbox -> host echo server
    iptables -I FORWARD -s "$SANDBOX_IP" -d "$HOST_IP" --dport "$ECHO_PORT" -p tcp -j ACCEPT
    # Allow established/related back
    iptables -I FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Drop everything else from sandbox (blocks external internet)
    iptables -I FORWARD -s "$SANDBOX_IP" ! -d "$HOST_IP" -j DROP

    echo "[netns] Done. Sandbox can reach $HOST_IP:$ECHO_PORT only."
    echo "[netns] Namespace path: /var/run/netns/$NETNS"
    ;;

destroy)
    echo "[netns] Removing iptables rules"
    iptables -D FORWARD -s "$SANDBOX_IP" -d "$HOST_IP" --dport "$ECHO_PORT" -p tcp -j ACCEPT 2>/dev/null
    iptables -D FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null
    iptables -D FORWARD -s "$SANDBOX_IP" ! -d "$HOST_IP" -j DROP 2>/dev/null

    echo "[netns] Removing veth pair"
    ip link del "$VETH_HOST" 2>/dev/null

    echo "[netns] Removing network namespace"
    ip netns del "$NETNS" 2>/dev/null

    echo "[netns] Cleaned up."
    ;;

*)
    echo "Unknown action: $ACTION"
    exit 1
    ;;
esac