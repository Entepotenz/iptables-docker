#!/bin/sh

set -o errexit
set -o nounset
if [ "${TRACE-0}" -eq 1 ]; then set -o xtrace; fi

cd "$(dirname "$0")" || exit 1

dir=$(pwd)

IP6T=$(which ip6tables)

interface=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")

WAN_IF=$(route | grep '^default' | grep -o '[^ ]*$')

readonly backup_dir_firwall_rules="/tmp/backup/firewall/"

#### util functions

beginswith() { case $2 in "$1"*) true;; *) false;; esac; }

skip_docker_ifaces() {
  
  ## Skip all the interfaces created by docker:
  ##    vethXXXXXX
  ##    docker0
  ##    docker_gwbridge
  ##    br-XXXXXXXXXXX

  ifaces=$(ip -o link show | awk -F': ' '{print $2}')

  for i in $ifaces
  do
      if beginswith vet "$i"; then
          vet_value=${i%%@*}
          echo "Allow traffic on vet iface: $vet_value"
          $IP6T -A INPUT -i "$vet_value" -j ACCEPT
          $IP6T -A OUTPUT -o "$vet_value" -j ACCEPT
      fi
      if beginswith br- "$i"; then
          echo "Allow traffic on br- iface: $i"
          $IP6T -A INPUT -i "$i" -j ACCEPT
          $IP6T -A OUTPUT -o "$i" -j ACCEPT
      fi
      if beginswith docker "$i"; then
          echo "Allow traffic on docker iface: $i"
          $IP6T -A INPUT -i "$i" -j ACCEPT
          $IP6T -A OUTPUT -o "$i" -j ACCEPT
      fi
  done
}

#### end util functions

start() {
    echo "############ <START> ##############"

    mkdir -p "$backup_dir_firwall_rules"
    IP6TABLES_SAVE_FILE="$backup_dir_firwall_rules/rules_v6_$(date +%Y%m%d%H%M%S%N)"

    touch "$IP6TABLES_SAVE_FILE"
    chmod 600 "$IP6TABLES_SAVE_FILE"
    ip6tables-save -c >"$IP6TABLES_SAVE_FILE"

    # Flush all rules and delete all chains
    # for a clean startup
    $IP6T -F
    $IP6T -X
    # Zero out all counters
    $IP6T -Z

    $IP6T -t filter --flush
    $IP6T -t nat    --flush
    $IP6T -t mangle --flush

    # Preserve docker rules
    docker_restore

    # Skip filter on docker ifaces
    skip_docker_ifaces

    ### BLOCK INPUT BY DEFAULT ALLOW OUTPUT ###
    $IP6T -P INPUT DROP
    $IP6T -P FORWARD DROP
    $IP6T -P OUTPUT ACCEPT

    # Enable free use of loopback interfaces
    $IP6T -A INPUT -i lo -j ACCEPT
    $IP6T -A OUTPUT -o lo -j ACCEPT

    ###############
    ###  INPUT  ###
    ###############

    # === anti scan ===
    $IP6T -N SCANS
    $IP6T -A SCANS -p tcp --tcp-flags FIN,URG,PSH FIN,URG,PSH -j DROP
    $IP6T -A SCANS -p tcp --tcp-flags ALL ALL -j DROP
    $IP6T -A SCANS -p tcp --tcp-flags ALL NONE -j DROP
    $IP6T -A SCANS -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
    ####################
    echo "[Anti-scan is ready]"

    #No spoofing
    if [ -e /proc/sys/net/ipv6/conf/all/ip_filter ]; then
        for filtre in /proc/sys/net/ipv6/conf/*/rp_filter
        do
            echo > 1 "$filtre"
        done
    fi
    # https://www.admin-magazin.de/Das-Heft/2014/04/Ein-Basisregelwerk-mit-IP6Tables/(offset)/4
    if [ -n "$WAN_IF" ]; then
      $IP6T -A INPUT ! -i lo -s ::1/128 -j DROP
      $IP6T -A INPUT -i "$WAN_IF" -s FC00::/7 -j DROP
      $IP6T -A FORWARD -s ::1/128 -j DROP
      $IP6T -A FORWARD -i "$WAN_IF" -s FC00::/7 -j DROP
    fi
    echo "[Anti-spoofing is ready]"

    # #No synflood
    # if [ -e /proc/sys/net/ipv6/tcp_syncookies ]; then
    #     echo 1 > /proc/sys/net/ipv6/tcp_syncookies
    # fi
    # echo "[Anti-synflood is ready]"

    ####################
    # === Clean particulars packets ===
    #Make sure NEW incoming tcp connections are SYN packets
    $IP6T -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
    # Packets with incoming fragments
    $IP6T -A INPUT -f -j DROP
    # incoming malformed XMAS packets
    $IP6T -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
    # Incoming malformed NULL packets
    $IP6T -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    #Drop broadcast
    $IP6T -A INPUT -m pkttype --pkt-type broadcast -j DROP

    # Reject connection attempts not initiated from the host
    $IP6T -A INPUT -p tcp --syn -j DROP

    # Allow return connections initiated from the host
    $IP6T -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow connections from SSH clients
    $IP6T -A INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
    
    # Other firewall rules
    # insert here your firewall rules

    # Allow HTTP and HTTPS traffic 
    $IP6T -A INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
    $IP6T -A INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT

    # Swarm mode - uncomment to enable swarm access (adjust source lan)
    # $IP6T -A INPUT -p tcp --dport 2377 -m state --state NEW -s fe80::/10 -j ACCEPT
    # $IP6T -A INPUT -p tcp --dport 7946 -m state --state NEW -s fe80::/10 -j ACCEPT
    # $IP6T -A INPUT -p udp --dport 7946 -m state --state NEW -s fe80::/10 -j ACCEPT
    # $IP6T -A INPUT -p udp --dport 4789 -m state --state NEW -s fe80::/10 -j ACCEPT

    # Accept all ICMP v6 packets
    $IP6T -A INPUT -p ipv6-icmp -j ACCEPT

    # Allow DHCPv6 from LAN only
    $IP6T -A INPUT -m state --state NEW -m udp -p udp -s fe80::/10 --dport 546 -j ACCEPT

    ###############
    ###   LOG   ###
    ###############

    $IP6T -N LOGGING
    $IP6T -A INPUT -j LOGGING
    $IP6T -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: " --log-level 4
    $IP6T -A LOGGING -j DROP
}

docker_restore() {
  awk -f "$dir/awk.firewall" <"$IP6TABLES_SAVE_FILE" | ip6tables-restore
}

stop() {
    ### OPEN ALL !!! ###
    echo "############ <STOP> ##############"

    mkdir -p "$backup_dir_firwall_rules"
    IP6TABLES_SAVE_FILE="$backup_dir_firwall_rules/rules_v6_$(date +%Y%m%d%H%M%S%N)"

    touch "$IP6TABLES_SAVE_FILE"
    chmod 600 "$IP6TABLES_SAVE_FILE"
    ip6tables-save -c >"$IP6TABLES_SAVE_FILE"

    # set the default policy to ACCEPT
    $IP6T --policy INPUT   ACCEPT
    $IP6T --policy OUTPUT  ACCEPT
    $IP6T --policy FORWARD ACCEPT

    $IP6T           --flush
    $IP6T -t nat    --flush
    $IP6T -t mangle --flush

    # Preserve docker rules
    docker_restore
 }

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    start
    ;;
  *)
    echo "systemctl {start|stop} ip6tables-docker.service" >&2
    echo "or" >&2
    echo "ip6tables-docker.sh {start|stop}" >&2
    exit 1
    ;;
esac

exit 0
