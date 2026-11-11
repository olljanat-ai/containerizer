# Secret values in OpenBao

The apps in the appliance's sandbox read their connection strings, secret settings and the settings a release
pipeline used to fill (`#{Api.Host}#`, `__Example.Mode__`) from the secret store (see
[External Secrets](external-secrets.md)). On the appliance you enter those values in
[OpenBao](https://openbao.org). It runs on the appliance and is served on its normal HTTPS port:

**`https://<CZ_HOSTNAME>/ui/`**. On the admin pages, **Secrets ↗** links there.

You don't have to look up which keys an app needs. Every two minutes the appliance makes one entry for each
component that has secrets, with an empty value for each key the component reads. You only type the values.

## Sign in as the administrator

User name `admin` (method **Username**). The password is in `/etc/containerizer/secrets/openbao-admin` (root only,
like Grafana's). Change it in OpenBao after the first sign-in. The appliance doesn't need it afterwards.

The `admin` user can:

- read and write every app's values;
- create users, groups and policies (to give operators access);
- turn on sign-in methods (for SSO).

It can't seal OpenBao, change its storage or create a root token.

## Fill in an app's values

1. **Secrets engines → apps**: one folder per app namespace, one entry per component
   (`apps/<namespace>/<component>`, KV version 2, so every save keeps the earlier versions).
2. Open the entry and choose **Create new version**. Fill in the values; leave a key empty if the app should
   keep its own value from `appsettings.json`. Save.
3. Within two minutes the appliance:
   - copies the filled values into the store;
   - has External Secrets Operator sync the app's Secret right away;
   - restarts the app's Deployments and StatefulSets that read it (CronJobs pick the values up at their next run).

The key names are environment variable names: `ConnectionStrings__Main` sets `ConnectionStrings:Main`,
`Api__Url` sets `Api:Url`. They match the **Secret store keys** in the app's `HARDENING.md`.

| What you see | Where it comes from |
| --- | --- |
| An empty key | Nobody has filled it yet. The app runs without it (with its `appsettings.json` value). |
| A key with a value you didn't type | Someone put it in the store by hand before OpenBao was there: it was taken over. |
| A key that is not there although `HARDENING.md` lists it | Another part of the appliance fills it (the [sandbox identity provider](sandbox-idp.md)'s client secret, [lab services](lab-services.md)' credentials): don't set it. |

Settings that are not secret (a URL with a token in it, say) are in the component's ConfigMap
`<component>-settings`, not in OpenBao: see [overview](overview.md#generated-output).

## Give operators their own apps (delegated access)

For every app namespace the appliance writes the policy **`app-<namespace>`**. It allows reading and changing
that namespace's entries (`apps/<namespace>/*`) and nothing else. An operator who has it sees the names of the
other namespaces, never their values.

Give operators that policy as a user or, better, through a group of your identity provider (next section). With
a user (**Access → Authentication methods → userpass → Create user**, or with the CLI):

```sh
export BAO_ADDR=https://<CZ_HOSTNAME>    # the CLI is `bao` (OpenBao) or `vault`; VAULT_ADDR works too
bao login -method=userpass username=admin
bao write auth/userpass/users/jdoe password='...' token_policies=app-shop,app-hr
```

You can write policies of your own, too: one per team over several namespaces, or read-only (`["read", "list"]`).
Don't edit `app-*`, `cz-admin` or `cz-sync`: the appliance rewrites `app-*` when it differs.

## Sign-in with your identity provider (OIDC / OAuth 2.0)

OpenBao signs people in through any OpenID Connect provider: Microsoft Entra ID, Okta, Keycloak, Google, GitLab,
and others. You register OpenBao as an application with the provider. Its groups then decide who gets which policy.

**1. Register an application at the provider**

- Type: web application, authorization code flow (confidential client with a client secret).
- Redirect URIs:
  - `https://<CZ_HOSTNAME>/ui/vault/auth/oidc/oidc/callback` (the web UI);
  - `http://localhost:8250/oidc/callback` (the `bao login -method=oidc` CLI).
- A `groups` claim in the ID token. In Entra ID: **Token configuration → Add groups claim → Security groups**. The
  claim then has the groups' object IDs. In Keycloak: a *Group Membership* mapper with *Full group path* off.
- Allow outbound HTTPS to the provider on the appliance's **Firewall** page (for Entra ID:
  `login.microsoftonline.com`).

**2. Turn on the OIDC method in OpenBao** (as `admin`)

```sh
bao auth enable oidc
bao write auth/oidc/config \
  oidc_discovery_url="https://login.microsoftonline.com/<tenant-id>/v2.0" \
  oidc_client_id="<client id>" oidc_client_secret="<client secret>" default_role=people
bao write auth/oidc/role/people \
  user_claim=email groups_claim=groups oidc_scopes=openid,profile,email \
  allowed_redirect_uris="https://<CZ_HOSTNAME>/ui/vault/auth/oidc/oidc/callback" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback" \
  token_ttl=8h token_policies=default
```

For Keycloak the discovery URL is `https://<keycloak>/realms/<realm>`; for Okta `https://<org>.okta.com`.

**3. Map the provider's groups to policies.** One external group per provider group, with an alias that is the
group's name or (Entra ID) object ID:

```sh
accessor=$(bao auth list -format=json | jq -r '."oidc/".accessor')
id=$(bao write -field=id identity/group name=shop-operators type=external policies=app-shop)
bao write identity/group-alias name="<group object ID or name>" mount_accessor="$accessor" canonical_id="$id"
# administrators: the admin policy
id=$(bao write -field=id identity/group name=containerizer-admins type=external policies=cz-admin)
bao write identity/group-alias name="<admins group>" mount_accessor="$accessor" canonical_id="$id"
```

People now choose **OIDC** on the sign-in page and get the policies of their groups. Keep the `admin` user (with a
strong password) as the way in when the provider is down.

The appliance's own sign-in ([Sign-in and roles](sign-in.md)) is separate: register Containerizer and OpenBao as
two applications with the same provider and use the same groups for both.

## How it works

- **Service.** OpenBao 2.7 runs as the container `cz-openbao` (systemd `containerizer-openbao.service`):
  - its own user, a read-only file system, no capabilities;
  - listens on 127.0.0.1:8200 only; Caddy serves `/ui/` and its API `/v1/` on port 443 with the appliance's
    certificate;
  - integrated (Raft) storage in `/var/lib/containerizer/openbao`.
- **Unsealing.** OpenBao unseals itself at every start with the static key
  `/etc/containerizer/secrets/openbao-unseal.key`, which `cz-firstboot` makes once. After a reboot nobody has to
  enter an unseal key. The data can't be read without that file.
- **Setup.** `cz-sandbox` runs `python -m containerizer.openbao sync` every two minutes, as root. The first run
  initialises OpenBao:
  - the mount `apps` (KV version 2), the `userpass` method with the user `admin`, the policies `cz-admin` and
    `cz-sync`;
  - a periodic token for the sync, kept in `secrets/openbao-sync-token`;
  - the recovery key, kept in `secrets/openbao-recovery-key`;
  - then it revokes the root token.
- **Sync.** Each run:
  - reads every component's `<component>-secrets` ExternalSecret in the sandbox, but only those that read their
    own namespace's key `<namespace>--<component>`;
  - adds the missing keys to `apps/<namespace>/<component>`, empty or with the value already in the store, and
    never overwrites a value that is there;
  - writes the filled values into the remote Secret `containerizer-secrets/<namespace>--<component>` with its own
    field manager (`containerizer-openbao`), so the keys of the other writers stay, and removes a key emptied in
    OpenBao;
  - writes the `app-<namespace>` policies.
- **The sandbox's ExternalSecrets.** In the sandbox (`sandbox/flux/apps`), each component's `<component>-secrets`
  ExternalSecret reads every key its remote Secret has (`dataFrom: extract`), and its annotation
  `containerizer.io/properties` keeps the list. A key that isn't filled is then just not set. With the generated
  list of properties, External Secrets Operator creates none of a Secret's keys while one is missing. The app
  folder's own manifests, for the real environment, keep the list.
- **The other values stay where they were.** The store is still the namespace `containerizer-secrets`, and the
  appliance's own writers fill it there: Git tokens, the Flux webhook, the sandbox identity provider, lab
  services. Secret files (`<component>-files`) and keytabs are set as before
  ([External Secrets](external-secrets.md#the-appliance-sandbox)).

## Backup and recovery

Back up `/var/lib/containerizer/openbao` together with `/etc/containerizer/secrets` (the unseal key, the recovery
key and the sync token): one without the other is of no use. See [Backup](appliance-admin.md#backup).

**Recovery.** If the sync token is lost (the log of `containerizer-sandbox.service` then says so), make a root
token with the recovery key, create a new sync token, and revoke the root token:

```sh
export BAO_ADDR=https://<CZ_HOSTNAME>
bao operator generate-root -init                     # prints a nonce and a one-time password (OTP)
bao operator generate-root -nonce=<nonce> "$(cat /etc/containerizer/secrets/openbao-recovery-key)"
bao operator generate-root -decode=<encoded token> -otp=<OTP>
BAO_TOKEN=<root token> bao token create -orphan -policy=cz-sync -no-default-policy -period=768h -field=token \
  > /etc/containerizer/secrets/openbao-sync-token && chmod 0400 /etc/containerizer/secrets/openbao-sync-token
BAO_TOKEN=<root token> bao token revoke -self
```

The appliance has no `bao` binary. Run these commands from your workstation against
`https://<CZ_HOSTNAME>`, or on the appliance with `docker exec -it cz-openbao bao ...` and
`BAO_ADDR=http://127.0.0.1:8200`.
