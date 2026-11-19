# Inventory: binaries, databases and external services

In a large estate it is easy to lose track of which repository builds which binary, which databases each
application uses and which external APIs and services it calls. The results site's **Inventory** page
(`/inventory`, linked from the front page) keeps that list for every application the scans assess, with a search
over every column.

| Tab | What it lists | From |
| --- | --- | --- |
| **Binaries** | The main binary of each component (`Orders.Api.dll`, the executable or package name), with its role and target framework | A-rated assessments only: what a build that can ship produces. A later scan rated lower leaves them as they were, so the list keeps the last A-rated build's names |
| **Databases** | Each connection string's database and server, with its type (SQL Server, PostgreSQL, MySQL, MongoDB, Redis, Oracle, Db2, SQLite) and the setting it is in. Never the user or password | `ConnectionStrings` and the database settings of `appsettings.json` (with the build's `appsettings.Release.json` transform and `appsettings.Production.json`), and the `<connectionStrings>` of `web.config` and `app.config` |
| **External services** | Each host the configuration or code names (URLs, broker and service addresses) with its port, scheme and the file and line, and each NServiceBus endpoint with its transport | The assessment's network needs (the same as the results page's [network connectivity](egress.md#network-connectivity)). Hosts inside the cluster, `localhost` and the databases' servers are left out |

Search for a binary to find the repository and application that build it, for a database or server to find every
application that uses it, or for a host to find every application that calls it. Each row links to its application's
results page and its repository.

Every scan updates the inventory. **First seen** and **last seen** say when each item was first and last found; an
item a later scan no longer finds is marked **removed** (tick **Also removed** to see those). The first update of the
results database to schema 60 fills the inventory from each application's latest assessment (its binaries from its
latest A-rated one): those items are first seen at that update. The databases come from scans made from 0.51.17 on.

![The inventory: the databases tab searched for a server](images/results-inventory.png#only-light){ .cz-shot }
![The inventory: the databases tab searched for a server](images/results-inventory-dark.png#only-dark){ .cz-shot }

**External services** lists each service once (its host and port), with how many applications use it and which
(hover over an application for its components and the files and lines that name the service). Pick a **port** from
the drop-down (each port there is, with how many services use it), and type part of an **FQDN or IP address** to
narrow the list down; the search box still searches every column.

![The inventory: external services on port 443, each with the applications that use it](images/results-inventory-services.png#only-light){ .cz-shot }
![The inventory: external services on port 443, each with the applications that use it](images/results-inventory-services-dark.png#only-dark){ .cz-shot }

The same lists are in the [API](api.md): `GET /api/v1/inventory/binaries`, `/databases` and `/services`, with the
same search and filters by application, product, name and server.

The table is `InventoryItem` in the results database and the view `vInventory` (application, product and business
unit as mapped now): the reader, writer and admin roles can query it, for reports of your own:

```sql
SELECT Name AS DatabaseName, Server, ApplicationName, ProductName, ComponentName, Source
FROM containerizer.vInventory
WHERE Kind = N'database' AND RemovedAt IS NULL
ORDER BY Server, Name;
```

## NServiceBus

NServiceBus endpoints are listed under **External services** as `NServiceBus: <transport>`, with the endpoint's
name and the NServiceBus version. How the scan finds the transport, and which transports the lab serves, is in
[Lab services](lab-services.md#nservicebus-endpoints).
