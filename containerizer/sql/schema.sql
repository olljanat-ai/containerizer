-- Containerizer results database (Microsoft SQL Server 2016 or later, Azure SQL Database).
-- Idempotent: `python -m containerizer db init` runs it on every upgrade. Batches are separated by GO.
--
--   cz.BusinessUnit 1─* cz.Product 1─* cz.Application 1─* cz.Component      (who owns what)
--   cz.Application 1─* cz.ApplicationAssessment 1─* cz.ComponentAssessment  (one row per scan)
--                                                1─* cz.Finding             (why, fix, references)
--
-- The scan fills Application, Component and the assessment tables. People fill BusinessUnit and
-- Product and set Application.ProductId / Product.BusinessUnitId; a scan never overwrites them.
-- See docs/results-database.md.

IF SCHEMA_ID(N'cz') IS NULL EXEC(N'CREATE SCHEMA cz AUTHORIZATION dbo');
GO

IF OBJECT_ID(N'cz.SchemaVersion', N'U') IS NULL
CREATE TABLE cz.SchemaVersion (
    Version     int          NOT NULL CONSTRAINT PK_SchemaVersion PRIMARY KEY,
    AppliedAt   datetime2(0) NOT NULL CONSTRAINT DF_SchemaVersion_AppliedAt DEFAULT SYSUTCDATETIME()
);
GO

-- Plain-language meaning of the ratings, for people reading the tables directly.
IF OBJECT_ID(N'cz.Rating', N'U') IS NULL
CREATE TABLE cz.Rating (
    Rating      char(1)       NOT NULL CONSTRAINT PK_Rating PRIMARY KEY,
    Title       nvarchar(100) NOT NULL,
    Description nvarchar(400) NOT NULL,
    SortOrder   tinyint       NOT NULL
);
GO

IF OBJECT_ID(N'cz.BusinessUnit', N'U') IS NULL
CREATE TABLE cz.BusinessUnit (
    BusinessUnitId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_BusinessUnit PRIMARY KEY,
    Name           nvarchar(200)  NOT NULL CONSTRAINT UQ_BusinessUnit_Name UNIQUE,
    Description    nvarchar(1000) NULL,
    Owner          nvarchar(200)  NULL,
    CreatedAt      datetime2(0)   NOT NULL CONSTRAINT DF_BusinessUnit_CreatedAt DEFAULT SYSUTCDATETIME()
);
GO

IF OBJECT_ID(N'cz.Product', N'U') IS NULL
CREATE TABLE cz.Product (
    ProductId      int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Product PRIMARY KEY,
    Name           nvarchar(200)  NOT NULL CONSTRAINT UQ_Product_Name UNIQUE,
    Description    nvarchar(1000) NULL,
    Owner          nvarchar(200)  NULL,
    BusinessUnitId int            NULL CONSTRAINT FK_Product_BusinessUnit REFERENCES cz.BusinessUnit (BusinessUnitId),
    CreatedAt      datetime2(0)   NOT NULL CONSTRAINT DF_Product_CreatedAt DEFAULT SYSUTCDATETIME()
);
GO

-- One row per assessed application (a repository, or an app folder in one). SourceKey is the stable
-- identity the scan matches on: "<git remote URL>#<folder in the repository>", or the app name.
IF OBJECT_ID(N'cz.Application', N'U') IS NULL
CREATE TABLE cz.Application (
    ApplicationId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Application PRIMARY KEY,
    SourceKey     nvarchar(400)  NOT NULL CONSTRAINT UQ_Application_SourceKey UNIQUE,
    Name          nvarchar(200)  NOT NULL,          -- from the scan (folder name)
    DisplayName   nvarchar(200)  NULL,              -- set by people; shown instead of Name
    Description   nvarchar(1000) NULL,              -- set by people
    Owner         nvarchar(200)  NULL,              -- set by people
    ProductId     int            NULL CONSTRAINT FK_Application_Product REFERENCES cz.Product (ProductId),
    RepositoryUrl nvarchar(400)  NULL,
    SourcePath    nvarchar(400)  NULL,              -- folder in the repository
    FirstSeenAt   datetime2(0)   NOT NULL CONSTRAINT DF_Application_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    LastSeenAt    datetime2(0)   NOT NULL CONSTRAINT DF_Application_LastSeenAt DEFAULT SYSUTCDATETIME(),
    Retired       bit            NOT NULL CONSTRAINT DF_Application_Retired DEFAULT 0  -- set by people: hide from the UI
);
GO

-- A deployable part of an application (web site, service, worker, desktop client, ...), matched by
-- its project file path inside the application. Created and mapped to its application by the scan.
IF OBJECT_ID(N'cz.Component', N'U') IS NULL
CREATE TABLE cz.Component (
    ComponentId   int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Component PRIMARY KEY,
    ApplicationId int           NOT NULL CONSTRAINT FK_Component_Application REFERENCES cz.Application (ApplicationId),
    ProjectPath   nvarchar(400) NOT NULL,
    Name          nvarchar(200) NOT NULL,
    FirstSeenAt   datetime2(0)  NOT NULL CONSTRAINT DF_Component_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    LastSeenAt    datetime2(0)  NOT NULL CONSTRAINT DF_Component_LastSeenAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_Component_Path UNIQUE (ApplicationId, ProjectPath)
);
GO

-- One row per scan of an application. History is kept; the views pick the latest.
IF OBJECT_ID(N'cz.ApplicationAssessment', N'U') IS NULL
CREATE TABLE cz.ApplicationAssessment (
    AssessmentId   int IDENTITY(1,1) NOT NULL CONSTRAINT PK_ApplicationAssessment PRIMARY KEY,
    ApplicationId  int            NOT NULL CONSTRAINT FK_ApplicationAssessment_Application REFERENCES cz.Application (ApplicationId),
    AssessedAt     datetime2(0)   NOT NULL CONSTRAINT DF_ApplicationAssessment_AssessedAt DEFAULT SYSUTCDATETIME(),
    Rating         char(1)        NOT NULL CONSTRAINT FK_ApplicationAssessment_Rating REFERENCES cz.Rating (Rating),
    Score          int            NOT NULL,         -- readiness 0-100
    EffortDays     decimal(9,1)   NOT NULL,         -- estimated person-days
    Confidence     decimal(4,2)   NOT NULL,         -- 0-1, how sure the rules are
    Summary        nvarchar(2000) NOT NULL,
    Verified       bit            NOT NULL CONSTRAINT DF_ApplicationAssessment_Verified DEFAULT 0, -- built and run (analyze)
    SourceCommit   nvarchar(64)   NULL,
    SourceBranch   nvarchar(200)  NULL,
    ToolVersion    nvarchar(64)   NULL,
    ReportJson     nvarchar(max)  NULL              -- the full assessment.json entry
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_ApplicationAssessment_App' AND object_id = OBJECT_ID(N'cz.ApplicationAssessment'))
CREATE INDEX IX_ApplicationAssessment_App ON cz.ApplicationAssessment (ApplicationId, AssessedAt DESC, AssessmentId DESC);
GO

IF OBJECT_ID(N'cz.ComponentAssessment', N'U') IS NULL
CREATE TABLE cz.ComponentAssessment (
    AssessmentId       int           NOT NULL CONSTRAINT FK_ComponentAssessment_Assessment REFERENCES cz.ApplicationAssessment (AssessmentId) ON DELETE CASCADE,
    ComponentId        int           NOT NULL CONSTRAINT FK_ComponentAssessment_Component REFERENCES cz.Component (ComponentId),
    Role               nvarchar(40)  NOT NULL,      -- web, worker, console, desktop, ...
    Tier               nvarchar(40)  NOT NULL,      -- server, platform, database, client, other
    TargetFramework    nvarchar(200) NULL,
    Verdict            nvarchar(20)  NOT NULL,      -- info, config, refactor, rewrite, blocker
    VerdictText        nvarchar(200) NOT NULL,
    Score              int           NOT NULL,
    EffortDays         decimal(9,1)  NOT NULL,
    Confidence         decimal(4,2)  NOT NULL,
    WindowsContainerOk bit           NOT NULL,      -- a Windows container is a workable stop-gap
    VerifyStatus       nvarchar(40)  NULL,          -- ok, ok-external, finding, build-failed, run-failed (analyze only)
    VerifyDetail       nvarchar(2000) NULL,
    CONSTRAINT PK_ComponentAssessment PRIMARY KEY (AssessmentId, ComponentId)
);
GO

-- ComponentId NULL: a finding about the repository as a whole.
IF OBJECT_ID(N'cz.Finding', N'U') IS NULL
CREATE TABLE cz.Finding (
    FindingId    bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_Finding PRIMARY KEY,
    AssessmentId int            NOT NULL CONSTRAINT FK_Finding_Assessment REFERENCES cz.ApplicationAssessment (AssessmentId) ON DELETE CASCADE,
    ComponentId  int            NULL CONSTRAINT FK_Finding_Component REFERENCES cz.Component (ComponentId),
    RuleId       nvarchar(200)  NOT NULL,
    Severity     nvarchar(20)   NOT NULL,           -- as it counts for this component
    RuleSeverity nvarchar(20)   NOT NULL,           -- as written in the rule
    Category     nvarchar(100)  NULL,
    Title        nvarchar(400)  NOT NULL,
    Why          nvarchar(max)  NULL,
    Fix          nvarchar(max)  NULL,
    EffortDays   decimal(9,2)   NULL,
    Via          nvarchar(200)  NULL,               -- library the finding comes from
    OnlyCommands nvarchar(400)  NULL,               -- only these optional commands are affected
    Evidence     nvarchar(2000) NULL,
    Refs         nvarchar(max)  NULL,               -- JSON array of reference URLs
    Source       nvarchar(40)   NULL                -- curated, learned, runtime
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Finding_Assessment' AND object_id = OBJECT_ID(N'cz.Finding'))
CREATE INDEX IX_Finding_Assessment ON cz.Finding (AssessmentId, ComponentId);
GO

MERGE cz.Rating AS t
USING (VALUES
    ('A', N'Lift and shift', N'Containers with configuration only', 1),
    ('B', N'Minor refactoring', N'Small code changes', 2),
    ('C', N'Major refactoring', N'Framework port needed', 3),
    ('D', N'Partial', N'Some components must stay on Windows', 4),
    ('E', N'Not feasible', N'Core depends on Windows-only technology', 5)
) AS s (Rating, Title, Description, SortOrder)
ON t.Rating = s.Rating
WHEN MATCHED THEN UPDATE SET Title = s.Title, Description = s.Description, SortOrder = s.SortOrder
WHEN NOT MATCHED THEN INSERT (Rating, Title, Description, SortOrder) VALUES (s.Rating, s.Title, s.Description, s.SortOrder);
GO

-- Latest assessment of every application, with its product and business unit ("(not assigned)" when
-- nobody has mapped it yet). This is what the web UI reads.
CREATE OR ALTER VIEW cz.vApplicationLatest AS
SELECT a.ApplicationId,
       COALESCE(a.DisplayName, a.Name) AS ApplicationName,
       a.Name AS ScanName, a.Description, a.Owner, a.RepositoryUrl, a.SourcePath,
       p.ProductId, p.Name AS ProductName, p.Owner AS ProductOwner,
       bu.BusinessUnitId, bu.Name AS BusinessUnitName, bu.Owner AS BusinessUnitOwner,
       x.AssessmentId, x.AssessedAt, x.Rating, r.Title AS RatingTitle, r.Description AS RatingDescription,
       x.Score, x.EffortDays, x.Confidence, x.Summary, x.Verified, x.SourceCommit, x.SourceBranch
FROM cz.Application a
CROSS APPLY (SELECT TOP (1) * FROM cz.ApplicationAssessment aa
             WHERE aa.ApplicationId = a.ApplicationId
             ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) x
JOIN cz.Rating r ON r.Rating = x.Rating
LEFT JOIN cz.Product p ON p.ProductId = a.ProductId
LEFT JOIN cz.BusinessUnit bu ON bu.BusinessUnitId = p.BusinessUnitId
WHERE a.Retired = 0;
GO

CREATE OR ALTER VIEW cz.vComponentLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.ProductName, l.BusinessUnitName, l.AssessmentId,
       c.ComponentId, c.Name AS ComponentName, c.ProjectPath,
       ca.Role, ca.Tier, ca.TargetFramework, ca.Verdict, ca.VerdictText, ca.Score, ca.EffortDays,
       ca.Confidence, ca.WindowsContainerOk, ca.VerifyStatus, ca.VerifyDetail
FROM cz.vApplicationLatest l
JOIN cz.ComponentAssessment ca ON ca.AssessmentId = l.AssessmentId
JOIN cz.Component c ON c.ComponentId = ca.ComponentId;
GO

CREATE OR ALTER VIEW cz.vFindingLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.AssessmentId, f.ComponentId, c.Name AS ComponentName,
       f.FindingId, f.RuleId, f.Severity, f.RuleSeverity, f.Category, f.Title, f.Why, f.Fix, f.EffortDays,
       f.Via, f.OnlyCommands, f.Evidence, f.Refs, f.Source
FROM cz.vApplicationLatest l
JOIN cz.Finding f ON f.AssessmentId = l.AssessmentId
LEFT JOIN cz.Component c ON c.ComponentId = f.ComponentId;
GO

-- Applications nobody has mapped to a product yet, and products without a business unit.
CREATE OR ALTER VIEW cz.vUnmapped AS
SELECT N'Application' AS Kind, a.ApplicationId AS Id, COALESCE(a.DisplayName, a.Name) AS Name, a.RepositoryUrl AS Detail
FROM cz.Application a WHERE a.ProductId IS NULL AND a.Retired = 0
UNION ALL
SELECT N'Product', p.ProductId, p.Name, NULL FROM cz.Product p WHERE p.BusinessUnitId IS NULL;
GO

-- Least-privilege roles. Add database users to them (docs/results-database.md):
--   cz_writer: the scanner; inserts results, never touches the people-maintained columns
--   cz_reader: the web UI and report readers; views and lookup tables only
--   cz_mapper: people who maintain business units, products and the application mapping
IF DATABASE_PRINCIPAL_ID(N'cz_writer') IS NULL CREATE ROLE cz_writer;
IF DATABASE_PRINCIPAL_ID(N'cz_reader') IS NULL CREATE ROLE cz_reader;
IF DATABASE_PRINCIPAL_ID(N'cz_mapper') IS NULL CREATE ROLE cz_mapper;
GO
GRANT SELECT ON cz.Rating TO cz_writer;
GRANT SELECT, INSERT ON cz.ApplicationAssessment TO cz_writer;
GRANT SELECT, INSERT ON cz.ComponentAssessment TO cz_writer;
GRANT SELECT, INSERT ON cz.Finding TO cz_writer;
GRANT SELECT, INSERT ON cz.Application TO cz_writer;
GRANT UPDATE ON cz.Application (Name, RepositoryUrl, SourcePath, LastSeenAt) TO cz_writer;
GRANT SELECT, INSERT ON cz.Component TO cz_writer;
GRANT UPDATE ON cz.Component (Name, LastSeenAt) TO cz_writer;
GRANT SELECT ON cz.SchemaVersion TO cz_writer;

GRANT SELECT ON cz.vApplicationLatest TO cz_reader;
GRANT SELECT ON cz.vComponentLatest TO cz_reader;
GRANT SELECT ON cz.vFindingLatest TO cz_reader;
GRANT SELECT ON cz.vUnmapped TO cz_reader;
GRANT SELECT ON cz.Rating TO cz_reader;
GRANT SELECT ON cz.BusinessUnit TO cz_reader;
GRANT SELECT ON cz.Product TO cz_reader;
GRANT SELECT ON cz.ApplicationAssessment (AssessmentId, ApplicationId, AssessedAt, Rating, Score, EffortDays, Confidence, Verified) TO cz_reader;

GRANT SELECT, INSERT, UPDATE, DELETE ON cz.BusinessUnit TO cz_mapper;
GRANT SELECT, INSERT, UPDATE, DELETE ON cz.Product TO cz_mapper;
GRANT SELECT ON cz.Application TO cz_mapper;
GRANT UPDATE ON cz.Application (ProductId, DisplayName, Description, Owner, Retired) TO cz_mapper;
GRANT SELECT ON cz.vUnmapped TO cz_mapper;
GRANT SELECT ON cz.vApplicationLatest TO cz_mapper;
GO

IF NOT EXISTS (SELECT 1 FROM cz.SchemaVersion WHERE Version = 1) INSERT cz.SchemaVersion (Version) VALUES (1);
GO
