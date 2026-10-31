# API

Scripts and other tools can read the results and maintain the business units, products and
application mapping through a JSON API under `/api/v1`. It uses the same identity provider as the
[sign-in](sign-in.md), with OAuth access tokens instead of cookies.

## Turn it on

Add two settings to `/etc/containerizer/web.env` next to the sign-in ones and restart the web UI:

| Variable | Meaning |
| --- | --- |
| `CONTAINERIZER_API_AUDIENCE` | The audience access tokens must be issued for, e.g. `api://containerizer` (Entra ID: the Application ID URI of the app registration). |
| `CONTAINERIZER_API_CLIENTS` | Automation that may change everything, comma separated: `client:<client id>` (the token's `azp`, `appid` or `client_id`), or `role:`, `group:`, `email:`, `domain:`, `sub:` rules. Optional when the [roles](sign-in.md#roles) are enough. |

With **Entra ID**: set `accessTokenAcceptedVersion` to `2` in the API app's manifest so its access
tokens carry the same v2.0 issuer as the sign-in, define an app role (e.g. `Containerizer.Write`, allowed
member type Applications), grant it to the client app, and set
`CONTAINERIZER_API_CLIENTS=role:Containerizer.Write`.

## Authentication and authorization

Callers send `Authorization: Bearer <access token>`: the client-credentials flow for automation, or a
user's token. Signature, issuer, audience and expiry are checked; an ID token is refused (its audience is
the web app). Cookies are ignored, so there is no CSRF surface.

The roles apply to tokens too: admins and API clients can change everything, product owners only their
own products and applications (403 `forbidden` outside them), operators only read. A token that
matches none of these (viewers included) gets 403 `insufficient_scope`. Changes appear in the change history with **Via**
`API` and the user's e-mail, or `client:<client id>` for an application.

## Endpoints

Bodies are JSON (`Content-Type: application/json`, up to 64 KiB); unknown fields are refused.

| Method and path | Does |
| --- | --- |
| `GET /api/v1/business-units` · `POST` | list (`?name=`) · create `{"name", "owner", "description"}` |
| `GET` · `PATCH` · `PUT` · `DELETE /api/v1/business-units/{id}` | read · change some fields · replace · delete (409 while products are in it) |
| `GET /api/v1/products` · `POST` | list (`?name=`, `?businessUnitId=`) · create `{"name", "businessUnitId", "infoUrl", "owner", "description"}` |
| `GET` · `PATCH` · `PUT` · `DELETE /api/v1/products/{id}` | as above (409 while applications are mapped to it) |
| `GET /api/v1/applications` | list with the latest rating (`?unmapped=true`, `?productId=`, `?name=`, `?retired=true`) |
| `GET` · `PATCH /api/v1/applications/{id}` | read · set `productId`, `displayName`, `owner`, `description`, `retired` (applications themselves come from scans) |
| `GET /api/v1/audit` | the change history (`?table=Application`, `?rowId=`, `?limit=` up to 1000) |
| `GET /api/v1/applications/{id}/components/{cid}/sbom` | packages of one component with licence, policy status and CVEs; `?format=cyclonedx` for the CycloneDX document |
| `GET /api/v1/sbom/packages` | packages across the portfolio (`?businessUnitId=`, `?productId=`, `?licenseStatus=allowed,warn,denied,unknown`, `?vulnerable=true`, `?limit=` up to 10000) |
| `GET /api/v1/sbom/summary` | the numbers of the Dependencies and licences page (`?businessUnitId=`, `?productId=`) |

`businessUnitId` and `productId` filters take an id or `none` (not assigned). Errors are
`{"error": "...", "message": "..."}` with 400 (invalid field), 401 (no or bad token), 403 (not allowed),
404, 405, 409 (name taken, referenced row missing or still in use), 413 or 415.

## Example

```sh
# Entra ID client credentials (a second app registration as the client, granted the API's app role)
TOKEN=$(curl -s https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token \
  -d grant_type=client_credentials -d client_id=$CLIENT_ID -d client_secret=$CLIENT_SECRET \
  -d scope=api://containerizer/.default | jq -r .access_token)
API=https://containerizer.example.com/api/v1

# map every unmapped application from one repository to the Billing product
PRODUCT=$(curl -s -H "Authorization: Bearer $TOKEN" "$API/products?name=Billing" | jq '.items[0].id')
curl -s -H "Authorization: Bearer $TOKEN" "$API/applications?unmapped=true" \
  | jq -r '.items[] | select(.repositoryUrl == "https://dev.azure.com/contoso/Billing/_git/billing") | .id' \
  | while read id; do
      curl -s -X PATCH -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
        -d "{\"productId\": $PRODUCT}" "$API/applications/$id"
    done

# licences to review or denied in one business unit
curl -s -H "Authorization: Bearer $TOKEN" "$API/sbom/packages?businessUnitId=3&licenseStatus=warn,denied"
```
