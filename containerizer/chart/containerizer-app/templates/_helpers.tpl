{{/*
cz.merge: merge .src into the map .dst in place. Maps merge key by key, anything else replaces, and the
string "~unset" removes the key. containerizer/helmchart.py `merge` does the same.
*/}}
{{- define "cz.merge" -}}
{{- $dst := .dst -}}
{{- range $k, $v := .src -}}
{{- if and (kindIs "string" $v) (eq $v "~unset") -}}
{{- $_ := unset $dst $k -}}
{{- else if and (kindIs "map" $v) (kindIs "map" (get $dst $k)) -}}
{{- include "cz.merge" (dict "dst" (get $dst $k) "src" $v) -}}
{{- else -}}
{{- $_ := set $dst $k $v -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
cz.subst: .x as JSON with ${component} and ${partOf} filled in (fromJson it: a fresh copy).
*/}}
{{- define "cz.subst" -}}
{{- .x | toJson | replace "${component}" .component | replace "${partOf}" .partOf -}}
{{- end -}}

{{/*
cz.resolve: in the map .x, in place, every list item and map value "@<name>" becomes the fragment <name> (.fragments);
maps are walked into, in lists too; a list in a list is left as it is.
*/}}
{{- define "cz.resolve" -}}
{{- $frags := .fragments -}}
{{- $x := .x -}}
{{- range $k, $v := $x -}}
{{- if and (kindIs "string" $v) (hasPrefix "@" $v) (hasKey $frags (trimPrefix "@" $v)) -}}
{{- $_ := set $x $k (deepCopy (get $frags (trimPrefix "@" $v))) -}}
{{- else if kindIs "map" $v -}}
{{- include "cz.resolve" (dict "x" $v "fragments" $frags) -}}
{{- else if kindIs "slice" $v -}}
{{- $out := list -}}
{{- range $item := $v -}}
{{- if and (kindIs "string" $item) (hasPrefix "@" $item) (hasKey $frags (trimPrefix "@" $item)) -}}
{{- $out = append $out (deepCopy (get $frags (trimPrefix "@" $item))) -}}
{{- else -}}
{{- if kindIs "map" $item -}}
{{- include "cz.resolve" (dict "x" $item "fragments" $frags) -}}
{{- end -}}
{{- $out = append $out $item -}}
{{- end -}}
{{- end -}}
{{- $_ := set $x $k $out -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
cz.harden: the hardening of a pod, in place, after its values: no value can change or remove it. A pod that asks
for something it forbids is not rendered at all. containerizer/helmchart.py `harden` does the same.
  pod:        hostUsers false (own user namespace), no service account token, runAsNonRoot, seccomp RuntimeDefault;
              no hostNetwork, hostPID, hostIPC, hostPath volumes; only the safe sysctls
  containers: (and init containers) not privileged, no privilege escalation, read-only root file system,
              runAsNonRoot, seccomp RuntimeDefault, all capabilities dropped (at most NET_BIND_SERVICE added back),
              no hostPort, a memory limit
*/}}
{{- define "cz.harden" -}}
{{- $pod := .pod -}}
{{- $where := .where -}}
{{- range $k := list "hostNetwork" "hostPID" "hostIPC" -}}
{{- if get $pod $k -}}{{- fail (printf "%s: %s is not allowed by the shared chart" $where $k) -}}{{- end -}}
{{- end -}}
{{- $_ := set $pod "hostUsers" false -}}
{{- $_ := set $pod "automountServiceAccountToken" false -}}
{{- $psc := $pod.securityContext | default dict -}}
{{- $_ := set $psc "runAsNonRoot" true -}}
{{- $_ := set $psc "seccompProfile" (dict "type" "RuntimeDefault") -}}
{{- $safe := list "kernel.shm_rmid_forced" "net.ipv4.ip_local_port_range" "net.ipv4.ip_unprivileged_port_start" "net.ipv4.tcp_syncookies" "net.ipv4.ping_group_range" "net.ipv4.ip_local_reserved_ports" "net.ipv4.tcp_keepalive_time" "net.ipv4.tcp_fin_timeout" "net.ipv4.tcp_keepalive_intvl" "net.ipv4.tcp_keepalive_probes" -}}
{{- range $s := $psc.sysctls | default list -}}
{{- if not (has $s.name $safe) -}}{{- fail (printf "%s: sysctl %s is not allowed by the shared chart" $where $s.name) -}}{{- end -}}
{{- end -}}
{{- $_ := set $pod "securityContext" $psc -}}
{{- range $v := $pod.volumes | default list -}}
{{- if hasKey $v "hostPath" -}}{{- fail (printf "%s: hostPath volume %s is not allowed by the shared chart" $where $v.name) -}}{{- end -}}
{{- end -}}
{{- range $c := concat ($pod.containers | default list) ($pod.initContainers | default list) -}}
{{- $sc := $c.securityContext | default dict -}}
{{- $_ := set $sc "runAsNonRoot" true -}}
{{- $_ := set $sc "privileged" false -}}
{{- $_ := set $sc "allowPrivilegeEscalation" false -}}
{{- $_ := set $sc "readOnlyRootFilesystem" true -}}
{{- $_ := set $sc "seccompProfile" (dict "type" "RuntimeDefault") -}}
{{- $caps := $sc.capabilities | default dict -}}
{{- range $a := $caps.add | default list -}}
{{- if ne $a "NET_BIND_SERVICE" -}}{{- fail (printf "%s: capability %s is not allowed by the shared chart" $where $a) -}}{{- end -}}
{{- end -}}
{{- $_ := set $caps "drop" (list "ALL") -}}
{{- $_ := set $sc "capabilities" $caps -}}
{{- $_ := set $c "securityContext" $sc -}}
{{- range $p := $c.ports | default list -}}
{{- if $p.hostPort -}}{{- fail (printf "%s: hostPort %v is not allowed by the shared chart" $where $p.hostPort) -}}{{- end -}}
{{- end -}}
{{- if not (and $c.resources $c.resources.limits $c.resources.limits.memory) -}}
{{- fail (printf "%s: container %s has no memory limit" $where $c.name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
