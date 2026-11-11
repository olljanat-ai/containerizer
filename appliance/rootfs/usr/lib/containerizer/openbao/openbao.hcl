# OpenBao on the appliance (docs/openbao.md): the values of the sandbox apps' secrets. Listens on the loopback
# only; Caddy serves its UI and API on the appliance's HTTPS port (https://<appliance>/ui/). One node, Raft
# storage in /var/lib/containerizer/openbao. Unsealed with the static key /etc/containerizer/secrets/openbao-unseal.key
# at every start: no one has to type an unseal key after a reboot.
ui = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
log_level = "warn"

storage "raft" {
  path    = "/openbao/data"
  node_id = "appliance"
}

listener "tcp" {
  address         = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  # TLS ends at Caddy on the same host
  tls_disable     = true
  x_forwarded_for_authorized_addrs = "127.0.0.1/32"
}

seal "static" {
  current_key_id = "1"
  current_key    = "file:///openbao/unseal.key"
}
