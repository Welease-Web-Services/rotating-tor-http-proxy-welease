#!/bin/bash

function log() {
    if [[ $# == 1 ]]; then
        level="info"
        msg=$1
    elif [[ $# == 2 ]]; then
        level=$1
        msg=$2
    fi
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") [controller] [${level}] ${msg}"
}

if ((TOR_INSTANCES < 1)); then
    log "fatal" "Environment variable TOR_INSTANCES has to be at least 1"
    exit 1
fi

TOR_NEW_CIRCUIT_PERIOD="${TOR_NEW_CIRCUIT_PERIOD:-31536000}"
TOR_MAX_CIRCUIT_DIRTINESS="${TOR_MAX_CIRCUIT_DIRTINESS:-31536000}"
TOR_CONTROL_ENABLED="${TOR_CONTROL_ENABLED:-1}"
TOR_CONTROL_API_PORT="${TOR_CONTROL_API_PORT:-8080}"

if [[ "$TOR_CONTROL_ENABLED" == "1" ]] && [[ -z "$TOR_CONTROL_TOKEN" ]]; then
    log "fatal" "TOR_CONTROL_TOKEN is required when TOR_CONTROL_ENABLED=1"
    exit 2
fi

base_tor_socks_port=10000
base_tor_ctrl_port=20000
base_http_port=30000
round_robin_servers=""
sticky_auth_acls=""
sticky_routes=""
sticky_backends=""
deny_condition=""

log "Start creating a pool of ${TOR_INSTANCES} tor instances..."

# Reset torrc and apply runtime circuit settings.
cp /etc/tor/torrc.default /etc/tor/torrc
sed -i \
  -e "s/^NewCircuitPeriod .*/NewCircuitPeriod ${TOR_NEW_CIRCUIT_PERIOD}/" \
  -e "s/^MaxCircuitDirtiness .*/MaxCircuitDirtiness ${TOR_MAX_CIRCUIT_DIRTINESS}/" \
  /etc/tor/torrc
log "Tor circuit defaults: NewCircuitPeriod=${TOR_NEW_CIRCUIT_PERIOD}, MaxCircuitDirtiness=${TOR_MAX_CIRCUIT_DIRTINESS}"

if [[ -n $TOR_EXIT_COUNTRY ]]; then
    IFS=', ' read -r -a countries <<< "$TOR_EXIT_COUNTRY"
    value=""
    is_first=1
    for country in "${countries[@]}"
    do
        country=$(xargs <<< "$country")
        length=${#country}
        if [[ $length -ne 2 ]]; then
            continue
        fi
        if [[ $is_first -ne 1 ]]; then
            value="$value,"
        else
            is_first=0
        fi
        value="$value{$country}"
    done
    country_str=$(tr '[:upper:]' '[:lower:]' <<< "$value")
    if [[ -n $country_str ]]; then
        echo ExitNodes "$country_str" StrictNodes 1 >> /etc/tor/torrc
        log "Limited the exit nodes to countries: \"${TOR_EXIT_COUNTRY}\""
    fi
fi

if [[ -n "$PROXY_USER" ]] && [[ -n "$PROXY_PASSWORD" ]]; then
    AUTH_B64=$(echo -n "${PROXY_USER}:${PROXY_PASSWORD}" | base64 | tr -d '\n')
    sticky_auth_acls="${sticky_auth_acls}  acl auth_default req.hdr(Proxy-Authorization) -m str \"Basic ${AUTH_B64}\"\n"
    deny_condition="!auth_default"
    log "info" "Proxy authentication enabled for user ${PROXY_USER}."
fi

for ((i = 0; i < TOR_INSTANCES; i++)); do
    socks_port=$((base_tor_socks_port + i))
    ctrl_port=$((base_tor_ctrl_port + i))
    tor_data_dir="/var/local/tor/${i}"
    mkdir -p "${tor_data_dir}" && chmod -R 700 "${tor_data_dir}" && chown -R proxy: "${tor_data_dir}"
    (tor --PidFile "${tor_data_dir}/tor.pid" \
      --SocksPort 127.0.0.1:"${socks_port}" \
      --ControlPort 127.0.0.1:"${ctrl_port}" \
      --dataDirectory "${tor_data_dir}" 2>&1 |
      sed -r "s/^(\w+\ [0-9 :\.]+)(\[.*)[\r\n]?$/$(date -u +"%Y-%m-%dT%H:%M:%SZ") [tor#${i}] \2/") &

    http_port=$((base_http_port + i))
    privoxy_data_dir="/var/local/privoxy/${i}"
    mkdir -p "${privoxy_data_dir}" && chown -R proxy: "${privoxy_data_dir}"
    cp /etc/privoxy/config.templ "${privoxy_data_dir}/config"
    sed -i \
      -e 's@PLACEHOLDER_CONFDIR@'"${privoxy_data_dir}"'@g' \
      -e 's@PLACEHOLDER_HTTP_PORT@'"${http_port}"'@g' \
      -e 's@PLACEHOLDER_SOCKS_PORT@'"${socks_port}"'@g' \
      "${privoxy_data_dir}/config"
    (privoxy \
      --no-daemon \
      --pidfile "${privoxy_data_dir}/privoxy.pid" \
      "${privoxy_data_dir}/config" 2>&1 |
      sed -r "s/^([0-9\-]+\ [0-9:\.]+\ [0-9a-f]+\ )([^:]+):\ (.*)[\r\n]?$/$(date -u +"%Y-%m-%dT%H:%M:%SZ") [privoxy#${i}] [\L\2] \E\3/") &

    round_robin_servers="${round_robin_servers}  server privoxy${i} 127.0.0.1:${http_port} check\n"
    sticky_backends="${sticky_backends}\nbackend privoxy_slot${i}\n  server privoxy${i} 127.0.0.1:${http_port} check\n"

    if [[ -n "$PROXY_USER" ]] && [[ -n "$PROXY_PASSWORD" ]]; then
        SLOT_USER="${PROXY_USER}-s${i}"
        SLOT_AUTH_B64=$(echo -n "${SLOT_USER}:${PROXY_PASSWORD}" | base64 | tr -d '\n')
        sticky_auth_acls="${sticky_auth_acls}  acl auth_slot${i} req.hdr(Proxy-Authorization) -m str \"Basic ${SLOT_AUTH_B64}\"\n"
        sticky_routes="${sticky_routes}  use_backend privoxy_slot${i} if auth_slot${i}\n"
        deny_condition="${deny_condition} !auth_slot${i}"
    fi
done

{
cat <<'HAPROXY'
global
  log stdout format raw local0
  pidfile /var/local/haproxy/haproxy.pid
  maxconn 1024
  user proxy

defaults
  mode http
  log global
  log-format "%ST %B %{+Q}r"
  option dontlognull
  option http-server-close
  option forwardfor except 127.0.0.0/8
  option redispatch
  retries 3
  timeout http-request 10s
  timeout queue 1m
  timeout connect 10s
  timeout client 1m
  timeout server 1m
  timeout http-keep-alive 10s
  timeout check 10s
  maxconn 1024

listen stats
  bind 0.0.0.0:4444
  mode http
  log global
  maxconn 30
  timeout client 100s
  timeout server 100s
  timeout connect 100s
  timeout queue 100s
  stats enable
  stats hide-version
  stats refresh 30s
  stats show-desc Rotating Tor HTTP proxy
  stats show-legends
  stats show-node
  stats uri /

frontend main
  bind 0.0.0.0:3128
HAPROXY
printf '%b' "$sticky_auth_acls"
if [[ -n "$deny_condition" ]]; then
    printf '  http-request deny deny_status 407 hdr Proxy-Authenticate "Basic realm=\\"Proxy\\"" if %s\n' "$deny_condition"
fi
printf '%b' "$sticky_routes"
cat <<'HAPROXY'
  default_backend privoxy
  mode http

backend privoxy
  balance roundrobin
HAPROXY
printf '%b' "$round_robin_servers"
printf '%b' "$sticky_backends"
} >/etc/haproxy/haproxy.cfg

if [[ "$TOR_CONTROL_ENABLED" == "1" ]]; then
    log "Starting Tor slot control API on port ${TOR_CONTROL_API_PORT}"
    python3 /control_api.py &
fi

(haproxy -db -- /etc/haproxy/haproxy.cfg 2>&1 |
  sed -r "s/^(\[[^]]+]\ )?([\ 0-9\/\():]+)?(.*)[\r\n]?$/$(date -u +"%Y-%m-%dT%H:%M:%SZ") [haproxy] \L\1\E\3/") &

log "Wait 15 seconds to build the first Tor circuit"
sleep 15
if [[ -n "$PROXY_USER" ]] && [[ -n "$PROXY_PASSWORD" ]]; then
    curl -sx "http://${PROXY_USER}:${PROXY_PASSWORD}@127.0.0.1:3128" https://www.apple.com >/dev/null
else
    curl -sx "http://127.0.0.1:3128" https://www.apple.com >/dev/null
fi

while :; do
    sleep 3600
    log "Tor proxy pool alive with ${TOR_INSTANCES} sticky slots"
done
