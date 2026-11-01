# Lab sandbox: k3s, Flux, External Secrets, Gitea

The appliance's sandbox deployment path on the development server, so features that deploy to the
sandbox through GitOps can be tested end to end. The full description is in the repository:
`docs/local-dev-server.md`, section *Lab sandbox (k3s, Flux, Git server)*. The scripts are versioned in
`ci/lab-sandbox/`; this folder (`LAB_DIR`, default `/home/dev/lab-sandbox`) keeps a copy and the state.

```sh
./up.sh          # install or start everything (idempotent; needs sudo)
./status.sh      # what runs, Flux and External Secrets objects
./smoke.sh       # end-to-end test: local image, commit, Flux, pods Ready without a pull, sandbox verify
./smoke.sh --remove
./secret.sh <remote-key> '<json object>' | '<literal>' | @file | -    # a value in the secret store
./sync.sh        # one pass of the cz-sandbox equivalent (the timer runs it every 2 minutes)
./down.sh        # stop (data kept);  ./down.sh --purge  removes the cluster, Gitea and all state
. ./env.sh       # variables for a scan, a runner or `containerizer sandbox verify`
```

| What | Where |
| --- | --- |
| k3s v1.37.1+k3s1 (`docker: true`), systemd `k3s-lab` | API `https://127.0.0.1:6443`, admin kubeconfig `kubeconfig` (600) |
| Flux v2.10.0, External Secrets 2.14.0, ClusterSecretStore `app-secrets` | in k3s (`flux-system`, `external-secrets`, values in `containerizer-secrets`) |
| Gitea (`lab-git` container) | `https://lab-git:3001/` (host: 127.0.0.1:3001 and 172.17.0.1:3001; pods: CoreDNS maps `lab-git` to 172.17.0.1) |
| Output repository | `https://lab-git:3001/lab/sandbox-deployments.git` |
| Traefik | NodePorts on loopback: `http://127.0.0.1:30080`, `https://127.0.0.1:30443`, default certificate `*.sandbox.lab.test` |
| Sync (cz-sandbox equivalent), systemd `lab-sandbox-sync.timer` | every 2 minutes, runs `sync.sh` as this user |
| Credentials | `secrets.env` (600): Gitea admin `lab-admin` password, write token (output repository), read-only token (Flux) |
| Read-only verifier | `verifier.kubeconfig` (24-hour token, renewed by the timer) |
| Lab CA | `state/pki/ca.crt` (git trusts it for `https://lab-git:3001/` only, in `~/.gitconfig`) |

Images: pods use Docker's image store. `docker build -t localhost/lab/<app>/<component>:<tag>` and a
manifest with that `image:` (`imagePullPolicy: IfNotPresent`, which containerizer generates) runs
without a registry. Nothing is pushed or pulled; the appliance itself still pushes to its registry at
`localhost:5000`.
