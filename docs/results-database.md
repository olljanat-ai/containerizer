# Results database and web UI

Assessments can be written to a Microsoft SQL Server database, and a small read-only web UI shows them
to management grouped as **business unit → product → application → components**, with the rating,
the main obstacles and, for every component, what needs to change, why, and where to read more.

- The **scan** fills applications, their components and the results. Components are mapped to their
  application automatically (by project file path inside the application), and an application is
  recognised again on the next scan by its git remote and folder, so history builds up per application.
- **People** maintain business units and products, and which application belongs to which product, by
  editing three tables directly with SQL (examples below). A scan never overwrites those columns.

```
cz.BusinessUnit 1─* cz.Product 1─* cz.Application 1─* cz.Component            people / scan
                                    cz.Application 1─* cz.ApplicationAssessment   one per scan
                                                         1─* cz.ComponentAssessment
                                                         1─* cz.Finding           why, fix, references
```

The schema is in [`containerizer/sql/schema.sql`](../containerizer/sql/schema.sql) (SQL Server 2016 or
later, or Azure SQL Database).

## Quick start (local, Docker)

```sh
cp results/.env.example results/.env          # set four strong passwords
docker compose -f results/compose.yaml up -d --build
# http://127.0.0.1:8080/ shows the (empty) portfolio

# scan an app into it, static analysis only (mount it under its real folder name):
docker compose -f results/compose.yaml run --rm -v "$PWD/../my-app:/apps/my-app:ro" scan assess /apps/my-app

# or from a checkout, with build-and-run verification (needs Docker and pip install -r requirements-sql.txt):
export CONTAINERIZER_SQL="Server=127.0.0.1,1433;Database=Containerizer;User Id=cz_scanner;TrustServerCertificate=yes"
export CONTAINERIZER_SQL_PASSWORD=...         # CZ_SCANNER_PASSWORD from results/.env
python -m containerizer analyze ../my-app
```

The compose stack runs SQL Server 2022 Developer edition, creates the database, the schema and three
logins (`cz_scanner`, `cz_web`, `cz_editor`, one per role below), and starts the web UI with a read-only
root filesystem, no Linux capabilities and `no-new-privileges`. All ports are published on 127.0.0.1
only. Developer edition is licensed for development and test, not production.

## Writing results

`assess` and `analyze` write to SQL Server when `--sql` or `CONTAINERIZER_SQL` is set:

```sh
export CONTAINERIZER_SQL="Server=tcp:sql.example.com,1433;Database=Containerizer;User Id=cz_scanner;Encrypt=yes"
export CONTAINERIZER_SQL_PASSWORD=...
python -m containerizer analyze path/to/repo        # or: assess path/to/repo
```

| Key | Meaning |
| --- | --- |
| `Server` | `host,port` (`tcp:` prefix allowed). Named instances (`host\instance`) are not supported: give the port. |
| `Database` / `Initial Catalog` | Database name. |
| `User Id` | SQL login. The password comes from `CONTAINERIZER_SQL_PASSWORD` (preferred: not visible in the process list or shell history) or `Password=`. |
| `Encrypt` | `yes` (default) or `no`. |
| `TrustServerCertificate` | `no` (default) validates the server certificate against the system CAs; `yes` skips validation (local development with a self-signed certificate only). |
| `CaFile` | PEM file with the CA that signed the server certificate, when it is not in the system store. |

The defaults match Microsoft ODBC Driver 18: encrypted, certificate validated. Only SQL authentication
is supported (the driver is pymssql/FreeTDS); Microsoft Entra ID tokens and Windows integrated
authentication are not.

In a pipeline, install `requirements-sql.txt` next to `requirements.txt` and set the two variables
from the pipeline's secret store. With the GitHub Action, set them on the step; assess mode then
writes the verified results (the gate mode on pull requests does not write):

```yaml
- uses: olljanat-ai/containerizer@main
  with:
    mode: assess
  env:
    CONTAINERIZER_SQL: "Server=tcp:sql.example.com,1433;Database=Containerizer;User Id=cz_scanner"
    CONTAINERIZER_SQL_PASSWORD: ${{ secrets.CONTAINERIZER_SQL_PASSWORD }}
```

Each run inserts one `cz.ApplicationAssessment` per application with its components, findings
(including runtime findings from `analyze`) and the full JSON report. Results from earlier runs can be
loaded too:

```sh
python -m containerizer db import containerizer-out/assessment.json --key-prefix "https://github.com/org/repo#"
```

The key prefix makes the application key match what a direct scan of the same repository would use
(`<repository URL>#<folder>`); without it the application name is the key.

## Setting up the database (production)

Run as a database owner once, and again after upgrading containerizer (it is idempotent):

```sh
CONTAINERIZER_SQL="Server=...;Database=Containerizer;User Id=<admin>" python -m containerizer db init
```

It creates the `cz` schema, the tables and views, and three database roles with least privilege:

| Role | For | Can |
| --- | --- | --- |
| `cz_writer` | the scanner (pipeline) | insert results; update only the scan-owned columns of `cz.Application` and `cz.Component` |
| `cz_reader` | the web UI, report readers | read the `cz.v*` views, ratings, business units, products; not the raw JSON reports |
| `cz_mapper` | people who maintain the mapping | edit `cz.BusinessUnit`, `cz.Product` and `ProductId`, `DisplayName`, `Description`, `Owner`, `Retired` of `cz.Application` |

Create one login per use and add it to a role, for example:

```sql
-- in master
CREATE LOGIN cz_scanner WITH PASSWORD = N'<strong password>', CHECK_POLICY = ON;
CREATE LOGIN cz_web     WITH PASSWORD = N'<strong password>', CHECK_POLICY = ON;
-- in the Containerizer database
CREATE USER cz_scanner FOR LOGIN cz_scanner;  ALTER ROLE cz_writer ADD MEMBER cz_scanner;
CREATE USER cz_web     FOR LOGIN cz_web;      ALTER ROLE cz_reader ADD MEMBER cz_web;
-- people who edit the mapping: their own Windows/Entra logins
CREATE USER [CONTOSO\jane] FOR LOGIN [CONTOSO\jane];  ALTER ROLE cz_mapper ADD MEMBER [CONTOSO\jane];
```

On Azure SQL Database use contained users instead (`CREATE USER cz_web WITH PASSWORD = ...`, and
`CREATE USER [jane@contoso.com] FROM EXTERNAL PROVIDER` for people). Keep the scanner and web
passwords in your pipeline's secret store.

### TLS

The server must present a certificate the client trusts. With an internal CA, either add the CA to
the system store of the machine or container that runs containerizer, or pass `CaFile=/path/ca.pem`.
Azure SQL Database certificates are trusted by default. Use `TrustServerCertificate=yes` only for a
local development server.

## Mapping applications to products and business units

Do this with SQL Server Management Studio, Azure Data Studio, `sqlcmd` or any SQL client, as a member
of `cz_mapper`. Applications appear after their first scan. Names are unique, so the examples look
rows up by name.

**1. Create business units**

```sql
INSERT cz.BusinessUnit (Name, Owner, Description)
VALUES (N'Finance', N'CFO office', N'Finance and accounting'),
       (N'Operations', N'COO office', NULL);
```

**2. Create products and put each in a business unit**

```sql
INSERT cz.Product (Name, Owner, BusinessUnitId)
SELECT N'Billing', N'Jane Doe', BusinessUnitId FROM cz.BusinessUnit WHERE Name = N'Finance';

INSERT cz.Product (Name, BusinessUnitId)
SELECT N'Supply chain', BusinessUnitId FROM cz.BusinessUnit WHERE Name = N'Operations';
```

**3. See which applications still need a product**

```sql
SELECT * FROM cz.vUnmapped;       -- applications without a product, products without a business unit

SELECT ApplicationId, Name, RepositoryUrl, SourcePath FROM cz.Application
WHERE ProductId IS NULL AND Retired = 0 ORDER BY Name;
```

**4. Map applications to a product**

```sql
-- one application, by the name the scan gave it (its folder name)
UPDATE cz.Application
SET ProductId = (SELECT ProductId FROM cz.Product WHERE Name = N'Billing')
WHERE Name = N'meter-billing';

-- several at once
UPDATE a SET ProductId = p.ProductId
FROM cz.Application a JOIN cz.Product p ON p.Name = N'Supply chain'
WHERE a.Name IN (N'parts-catalog', N'dealer-orders', N'freight-rates');

-- everything from one repository (or an Azure DevOps project, a GitHub organisation, ...)
UPDATE a SET ProductId = p.ProductId
FROM cz.Application a JOIN cz.Product p ON p.Name = N'Billing'
WHERE a.RepositoryUrl LIKE N'https://dev.azure.com/contoso/Billing/%';
```

**5. Optional: friendlier names, owners, retiring an application**

```sql
UPDATE cz.Application
SET DisplayName = N'Parts Catalog', Owner = N'Supply chain team', Description = N'Dealer parts lookup'
WHERE Name = N'parts-catalog';

UPDATE cz.Application SET Retired = 1 WHERE Name = N'old-portal';   -- hidden from the UI, history kept
```

**Moving and renaming**

```sql
-- move a product to another business unit
UPDATE cz.Product SET BusinessUnitId = (SELECT BusinessUnitId FROM cz.BusinessUnit WHERE Name = N'Operations')
WHERE Name = N'Billing';

-- rename a business unit or product (everything mapped to it follows)
UPDATE cz.BusinessUnit SET Name = N'Group Finance' WHERE Name = N'Finance';

-- unmap
UPDATE cz.Application SET ProductId = NULL WHERE Name = N'meter-billing';
```

A product or business unit that still has rows mapped to it cannot be deleted (foreign key); unmap
them first. Each application belongs to one product and each product to one business unit.

When a repository moves (new remote URL), the next scan creates a new application row. Map it like
any other and retire the old one; its history stays in the database.

## Useful queries

```sql
-- portfolio by business unit and product
SELECT COALESCE(BusinessUnitName, N'(not assigned)') AS BusinessUnit,
       COALESCE(ProductName, N'(not assigned)') AS Product,
       ApplicationName, Rating, RatingTitle, Score, EffortDays, AssessedAt
FROM cz.vApplicationLatest ORDER BY BusinessUnit, Product, Rating, ApplicationName;

-- rating mix and effort per business unit
SELECT COALESCE(BusinessUnitName, N'(not assigned)') AS BusinessUnit, Rating, COUNT(*) AS Applications,
       SUM(EffortDays) AS EffortDays
FROM cz.vApplicationLatest GROUP BY BusinessUnitName, Rating ORDER BY BusinessUnit, Rating;

-- the most common blockers across the portfolio
SELECT Title, Severity, COUNT(DISTINCT ApplicationId) AS Applications
FROM cz.vFindingLatest WHERE Severity IN ('blocker', 'rewrite')
GROUP BY Title, Severity ORDER BY Applications DESC;

-- components of one application
SELECT ComponentName, Role, Verdict, VerdictText, EffortDays, VerifyStatus
FROM cz.vComponentLatest WHERE ApplicationName = N'parts-catalog';
```

## Web UI

```sh
CONTAINERIZER_SQL="Server=...;Database=Containerizer;User Id=cz_web" CONTAINERIZER_SQL_PASSWORD=... \
  python -m containerizer web            # http://127.0.0.1:8080/  (--host, --port)
```

or the `web` service of `results/compose.yaml` / the image built from `results/Dockerfile`.

- **Overview**: number of applications, how many are ready now, need code changes or are partly or not
  feasible, total estimated effort, the rating mix, then each business unit and product with its
  applications, their rating in words, readiness, effort and main obstacle. Filter by business unit
  with the buttons at the top.
- **Application**: rating and what it means, readiness, effort, confidence, main obstacles, the
  components (what each one is and its verdict), and per component every item to change with why, how
  to fix it and links to the documentation; the rating history.

It is read-only by design: GET and HEAD only, and the `cz_reader` login cannot change anything. Pages
are rendered on the server without JavaScript; all text is escaped; responses carry a strict
Content-Security-Policy (`default-src 'none'`), `X-Frame-Options: DENY`, `nosniff`,
`Referrer-Policy: no-referrer` and `no-store`; errors are logged on the server and never shown.

There is **no sign-in yet**. It listens on 127.0.0.1 unless `--host` says otherwise. Before making it
reachable by others, put it behind a reverse proxy or gateway that terminates TLS and authenticates
users (for example Entra ID application proxy, oauth2-proxy, or an ingress with authentication), and
do not publish it to the internet.
