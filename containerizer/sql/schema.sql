-- Containerizer results database (Microsoft SQL Server 2016 or later, Azure SQL Database).
-- Idempotent: `python -m containerizer db init` runs it on every upgrade. Batches are separated by GO.
--
-- Everything lives in one dedicated schema (default "containerizer", set with Schema= in the connection
-- string or CONTAINERIZER_SQL_SCHEMA), and the roles are named after it, so the tables can share a
-- database with other applications. Nothing is created in dbo.
--
--   BusinessUnit 1-* Product 1-* Application 1-* Component                     (who owns what)
--   Application 1-* ApplicationAssessment 1-* ComponentAssessment, Finding     (one per scan)
--   ComponentAssessment 0-1 ComponentMigration                                  (migration plan, agent prompt)
--   AuditLog: every change to BusinessUnit, Product and the mapping of Application, with who made it
--   AccessLog: who signed in to the web UI and what they looked at (optional)
--   RuleCandidate 1-* RuleEvidence: rules the learning loop learned, waiting for review (rule review)
--
-- The scan fills Application, Component and the assessment tables. People maintain business units,
-- products and the application mapping in the admin pages of the web UI; a scan never overwrites them.
-- See docs/results-database.md.

IF SCHEMA_ID(N'${schema}') IS NULL EXEC(N'CREATE SCHEMA [${schema}] AUTHORIZATION dbo');
GO

IF OBJECT_ID(N'[${schema}].SchemaVersion', N'U') IS NULL
CREATE TABLE [${schema}].SchemaVersion (
    Version     int          NOT NULL CONSTRAINT PK_SchemaVersion PRIMARY KEY,
    AppliedAt   datetime2(0) NOT NULL CONSTRAINT DF_SchemaVersion_AppliedAt DEFAULT SYSUTCDATETIME()
);
GO

-- Plain-language meaning of the ratings, for people reading the tables directly.
IF OBJECT_ID(N'[${schema}].Rating', N'U') IS NULL
CREATE TABLE [${schema}].Rating (
    Rating      char(1)       NOT NULL CONSTRAINT PK_Rating PRIMARY KEY,
    Title       nvarchar(100) NOT NULL,
    Description nvarchar(400) NOT NULL,
    SortOrder   tinyint       NOT NULL
);
GO

IF OBJECT_ID(N'[${schema}].BusinessUnit', N'U') IS NULL
CREATE TABLE [${schema}].BusinessUnit (
    BusinessUnitId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_BusinessUnit PRIMARY KEY,
    Name           nvarchar(200)  NOT NULL CONSTRAINT UQ_BusinessUnit_Name UNIQUE,
    Description    nvarchar(1000) NULL,
    Owner          nvarchar(200)  NULL,
    CreatedAt      datetime2(0)   NOT NULL CONSTRAINT DF_BusinessUnit_CreatedAt DEFAULT SYSUTCDATETIME()
);
GO

IF OBJECT_ID(N'[${schema}].Product', N'U') IS NULL
CREATE TABLE [${schema}].Product (
    ProductId      int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Product PRIMARY KEY,
    Name           nvarchar(200)  NOT NULL CONSTRAINT UQ_Product_Name UNIQUE,
    Description    nvarchar(1000) NULL,
    Owner          nvarchar(200)  NULL,
    BusinessUnitId int            NULL CONSTRAINT FK_Product_BusinessUnit REFERENCES [${schema}].BusinessUnit (BusinessUnitId),
    CreatedAt      datetime2(0)   NOT NULL CONSTRAINT DF_Product_CreatedAt DEFAULT SYSUTCDATETIME()
);
GO
-- Link to the product's page in another tool (CMDB, product catalogue, wiki); https only.
IF COL_LENGTH(N'[${schema}].Product', N'InfoUrl') IS NULL
ALTER TABLE [${schema}].Product ADD InfoUrl nvarchar(400) NULL
    CONSTRAINT CK_Product_InfoUrl CHECK (InfoUrl LIKE N'https://_%' AND InfoUrl NOT LIKE N'%[<>"'' ]%');
GO

-- One row per assessed application (a repository, or an app folder in one). SourceKey is the stable
-- identity the scan matches on: "<git remote URL>#<folder in the repository>", or the app name.
IF OBJECT_ID(N'[${schema}].Application', N'U') IS NULL
CREATE TABLE [${schema}].Application (
    ApplicationId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Application PRIMARY KEY,
    SourceKey     nvarchar(400)  NOT NULL CONSTRAINT UQ_Application_SourceKey UNIQUE,
    Name          nvarchar(200)  NOT NULL,          -- from the scan (folder name)
    DisplayName   nvarchar(200)  NULL,              -- set by people; shown instead of Name
    Description   nvarchar(1000) NULL,              -- set by people
    Owner         nvarchar(200)  NULL,              -- set by people
    ProductId     int            NULL CONSTRAINT FK_Application_Product REFERENCES [${schema}].Product (ProductId),
    RepositoryUrl nvarchar(400)  NULL,
    SourcePath    nvarchar(400)  NULL,              -- folder in the repository
    FirstSeenAt   datetime2(0)   NOT NULL CONSTRAINT DF_Application_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    LastSeenAt    datetime2(0)   NOT NULL CONSTRAINT DF_Application_LastSeenAt DEFAULT SYSUTCDATETIME(),
    Retired       bit            NOT NULL CONSTRAINT DF_Application_Retired DEFAULT 0  -- set by people: hide from the UI
);
GO

-- A deployable part of an application (web site, service, worker, desktop client, ...), matched by
-- its project file path inside the application. Created and mapped to its application by the scan.
IF OBJECT_ID(N'[${schema}].Component', N'U') IS NULL
CREATE TABLE [${schema}].Component (
    ComponentId   int IDENTITY(1,1) NOT NULL CONSTRAINT PK_Component PRIMARY KEY,
    ApplicationId int           NOT NULL CONSTRAINT FK_Component_Application REFERENCES [${schema}].Application (ApplicationId),
    ProjectPath   nvarchar(400) NOT NULL,
    Name          nvarchar(200) NOT NULL,
    FirstSeenAt   datetime2(0)  NOT NULL CONSTRAINT DF_Component_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    LastSeenAt    datetime2(0)  NOT NULL CONSTRAINT DF_Component_LastSeenAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_Component_Path UNIQUE (ApplicationId, ProjectPath)
);
GO

-- One row per scan of an application. History is kept; the views pick the latest.
IF OBJECT_ID(N'[${schema}].ApplicationAssessment', N'U') IS NULL
CREATE TABLE [${schema}].ApplicationAssessment (
    AssessmentId   int IDENTITY(1,1) NOT NULL CONSTRAINT PK_ApplicationAssessment PRIMARY KEY,
    ApplicationId  int            NOT NULL CONSTRAINT FK_ApplicationAssessment_Application REFERENCES [${schema}].Application (ApplicationId),
    AssessedAt     datetime2(0)   NOT NULL CONSTRAINT DF_ApplicationAssessment_AssessedAt DEFAULT SYSUTCDATETIME(),
    Rating         char(1)        NOT NULL CONSTRAINT FK_ApplicationAssessment_Rating REFERENCES [${schema}].Rating (Rating),
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
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_ApplicationAssessment_App' AND object_id = OBJECT_ID(N'[${schema}].ApplicationAssessment'))
CREATE INDEX IX_ApplicationAssessment_App ON [${schema}].ApplicationAssessment (ApplicationId, AssessedAt DESC, AssessmentId DESC);
GO

IF OBJECT_ID(N'[${schema}].ComponentAssessment', N'U') IS NULL
CREATE TABLE [${schema}].ComponentAssessment (
    AssessmentId       int           NOT NULL CONSTRAINT FK_ComponentAssessment_Assessment REFERENCES [${schema}].ApplicationAssessment (AssessmentId) ON DELETE CASCADE,
    ComponentId        int           NOT NULL CONSTRAINT FK_ComponentAssessment_Component REFERENCES [${schema}].Component (ComponentId),
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
IF OBJECT_ID(N'[${schema}].Finding', N'U') IS NULL
CREATE TABLE [${schema}].Finding (
    FindingId    bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_Finding PRIMARY KEY,
    AssessmentId int            NOT NULL CONSTRAINT FK_Finding_Assessment REFERENCES [${schema}].ApplicationAssessment (AssessmentId) ON DELETE CASCADE,
    ComponentId  int            NULL CONSTRAINT FK_Finding_Component REFERENCES [${schema}].Component (ComponentId),
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
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_Finding_Assessment' AND object_id = OBJECT_ID(N'[${schema}].Finding'))
CREATE INDEX IX_Finding_Assessment ON [${schema}].Finding (AssessmentId, ComponentId);
GO

-- Migration assistant (rules/migrations.yaml): for each component that is not ready, the concrete
-- replacements with effort estimates (PlanJson) and a self-contained prompt for an AI coding agent.
IF OBJECT_ID(N'[${schema}].ComponentMigration', N'U') IS NULL
CREATE TABLE [${schema}].ComponentMigration (
    AssessmentId  int            NOT NULL,
    ComponentId   int            NOT NULL,
    Outcome       nvarchar(40)   NOT NULL,         -- linux-container, partial, stays-on-windows
    EffortDays    decimal(9,1)   NOT NULL,         -- estimated person-days of the plan
    ItemCount     int            NOT NULL,
    PlanJson      nvarchar(max)  NOT NULL,         -- items: replace, with, kind, packages, steps, verify, refs, findings
    AgentPrompt   nvarchar(max)  NULL,             -- NULL when nothing in the component can be changed
    CONSTRAINT PK_ComponentMigration PRIMARY KEY (AssessmentId, ComponentId),
    CONSTRAINT FK_ComponentMigration_ComponentAssessment FOREIGN KEY (AssessmentId, ComponentId)
        REFERENCES [${schema}].ComponentAssessment (AssessmentId, ComponentId) ON DELETE CASCADE
);
GO

MERGE [${schema}].Rating AS t
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
CREATE OR ALTER VIEW [${schema}].vApplicationLatest AS
SELECT a.ApplicationId,
       COALESCE(a.DisplayName, a.Name) AS ApplicationName,
       a.Name AS ScanName, a.Description, a.Owner, a.RepositoryUrl, a.SourcePath,
       p.ProductId, p.Name AS ProductName, p.Owner AS ProductOwner, p.InfoUrl AS ProductInfoUrl,
       bu.BusinessUnitId, bu.Name AS BusinessUnitName, bu.Owner AS BusinessUnitOwner,
       x.AssessmentId, x.AssessedAt, x.Rating, r.Title AS RatingTitle, r.Description AS RatingDescription,
       x.Score, x.EffortDays, x.Confidence, x.Summary, x.Verified, x.SourceCommit, x.SourceBranch
FROM [${schema}].Application a
CROSS APPLY (SELECT TOP (1) * FROM [${schema}].ApplicationAssessment aa
             WHERE aa.ApplicationId = a.ApplicationId
             ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) x
JOIN [${schema}].Rating r ON r.Rating = x.Rating
LEFT JOIN [${schema}].Product p ON p.ProductId = a.ProductId
LEFT JOIN [${schema}].BusinessUnit bu ON bu.BusinessUnitId = p.BusinessUnitId
WHERE a.Retired = 0;
GO

CREATE OR ALTER VIEW [${schema}].vComponentLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.ProductName, l.BusinessUnitName, l.AssessmentId,
       c.ComponentId, c.Name AS ComponentName, c.ProjectPath,
       ca.Role, ca.Tier, ca.TargetFramework, ca.Verdict, ca.VerdictText, ca.Score, ca.EffortDays,
       ca.Confidence, ca.WindowsContainerOk, ca.VerifyStatus, ca.VerifyDetail
FROM [${schema}].vApplicationLatest l
JOIN [${schema}].ComponentAssessment ca ON ca.AssessmentId = l.AssessmentId
JOIN [${schema}].Component c ON c.ComponentId = ca.ComponentId;
GO

CREATE OR ALTER VIEW [${schema}].vFindingLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.AssessmentId, f.ComponentId, c.Name AS ComponentName,
       f.FindingId, f.RuleId, f.Severity, f.RuleSeverity, f.Category, f.Title, f.Why, f.Fix, f.EffortDays,
       f.Via, f.OnlyCommands, f.Evidence, f.Refs, f.Source
FROM [${schema}].vApplicationLatest l
JOIN [${schema}].Finding f ON f.AssessmentId = l.AssessmentId
LEFT JOIN [${schema}].Component c ON c.ComponentId = f.ComponentId;
GO

-- Every scan of every application (not only the latest), with the application's current product and
-- business unit and how many distinct obstacles that scan found. The trends page of the web UI reads it.
CREATE OR ALTER VIEW [${schema}].vAssessmentHistory AS
SELECT aa.AssessmentId, aa.ApplicationId, COALESCE(a.DisplayName, a.Name) AS ApplicationName,
       p.ProductId, p.Name AS ProductName, bu.BusinessUnitId, bu.Name AS BusinessUnitName,
       aa.AssessedAt, aa.Rating, aa.Score, aa.EffortDays, aa.Verified,
       COALESCE(f.Blockers, 0) AS Blockers, COALESCE(f.Rewrites, 0) AS Rewrites
FROM [${schema}].ApplicationAssessment aa
JOIN [${schema}].Application a ON a.ApplicationId = aa.ApplicationId
LEFT JOIN [${schema}].Product p ON p.ProductId = a.ProductId
LEFT JOIN [${schema}].BusinessUnit bu ON bu.BusinessUnitId = p.BusinessUnitId
OUTER APPLY (SELECT COUNT(DISTINCT CASE WHEN x.Severity = 'blocker' THEN x.RuleId END) AS Blockers,
                    COUNT(DISTINCT CASE WHEN x.Severity = 'rewrite' THEN x.RuleId END) AS Rewrites
             FROM [${schema}].Finding x
             WHERE x.AssessmentId = aa.AssessmentId AND x.Severity IN ('blocker', 'rewrite')) f
WHERE a.Retired = 0;
GO

CREATE OR ALTER VIEW [${schema}].vComponentMigrationLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.AssessmentId, m.ComponentId, c.Name AS ComponentName, c.ProjectPath,
       m.Outcome, m.EffortDays, m.ItemCount, m.PlanJson, m.AgentPrompt
FROM [${schema}].vApplicationLatest l
JOIN [${schema}].ComponentMigration m ON m.AssessmentId = l.AssessmentId
JOIN [${schema}].Component c ON c.ComponentId = m.ComponentId;
GO

-- Applications nobody has mapped to a product yet, and products without a business unit.
CREATE OR ALTER VIEW [${schema}].vUnmapped AS
SELECT N'Application' AS Kind, a.ApplicationId AS Id, COALESCE(a.DisplayName, a.Name) AS Name, a.RepositoryUrl AS Detail
FROM [${schema}].Application a WHERE a.ProductId IS NULL AND a.Retired = 0
UNION ALL
SELECT N'Product', p.ProductId, p.Name, NULL FROM [${schema}].Product p WHERE p.BusinessUnitId IS NULL;
GO

-- Rule review (docs/rule-review.md): what the learning loop learns waits here until a person approves or
-- rejects it. Fingerprint identifies what a rule does (not when or where it was learned), so the same
-- rule learned again adds evidence instead of a second candidate, and a rejected rule is not proposed
-- again. The scan proposes through ProposeRuleCandidate only (it cannot set a status); reviewers decide
-- through the admin login. Status changes are in the AuditLog.
IF OBJECT_ID(N'[${schema}].RuleCandidate', N'U') IS NULL
CREATE TABLE [${schema}].RuleCandidate (
    CandidateId    int IDENTITY(1,1) NOT NULL CONSTRAINT PK_RuleCandidate PRIMARY KEY,
    Kind           nvarchar(20)   NOT NULL CONSTRAINT CK_RuleCandidate_Kind CHECK (Kind IN (N'rule', N'failure', N'package')),
    Fingerprint    char(64)       NOT NULL CONSTRAINT UQ_RuleCandidate_Fingerprint UNIQUE,
    RuleId         nvarchar(200)  NOT NULL,
    Title          nvarchar(400)  NOT NULL,
    Source         nvarchar(40)   NOT NULL,         -- learned (build and run) or ai (proposed by the LLM)
    TargetFile     nvarchar(200)  NOT NULL,         -- ruleset file it is added to when approved
    RuleYaml       nvarchar(max)  NOT NULL,         -- the rule as learned
    Diff           nvarchar(max)  NULL,             -- unified diff of TargetFile when it was proposed
    Confidence     decimal(4,2)   NOT NULL,
    Model          nvarchar(200)  NULL,             -- the LLM that proposed it, if any
    LearnedFrom    nvarchar(400)  NULL,             -- application/component
    Status         nvarchar(20)   NOT NULL CONSTRAINT DF_RuleCandidate_Status DEFAULT N'pending'
                   CONSTRAINT CK_RuleCandidate_Status CHECK (Status IN (N'pending', N'approved', N'rejected')),
    SeenCount      int            NOT NULL CONSTRAINT DF_RuleCandidate_SeenCount DEFAULT 1,
    FirstSeenAt    datetime2(0)   NOT NULL CONSTRAINT DF_RuleCandidate_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    LastSeenAt     datetime2(0)   NOT NULL CONSTRAINT DF_RuleCandidate_LastSeenAt DEFAULT SYSUTCDATETIME(),
    ReviewedBy     nvarchar(256)  NULL,
    ReviewedByName nvarchar(256)  NULL,
    ReviewedAt     datetime2(0)   NULL,
    ReviewNote     nvarchar(1000) NULL,
    FinalYaml      nvarchar(max)  NULL,             -- the rule as approved (after the reviewer's edits)
    AppliedAs      nvarchar(20)   NULL,             -- pr or direct
    PullRequestUrl nvarchar(400)  NULL,
    ClaimedBy      nvarchar(256)  NULL,             -- a reviewer applying it right now (expires after 10 minutes)
    ClaimedAt      datetime2(0)   NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_RuleCandidate_Status' AND object_id = OBJECT_ID(N'[${schema}].RuleCandidate'))
CREATE INDEX IX_RuleCandidate_Status ON [${schema}].RuleCandidate (Status, LastSeenAt DESC);
GO

-- Why a rule was learned: one row each time a run learned it (the latest 20 are kept). Logs have
-- credentials masked before they are stored.
IF OBJECT_ID(N'[${schema}].RuleEvidence', N'U') IS NULL
CREATE TABLE [${schema}].RuleEvidence (
    EvidenceId     bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_RuleEvidence PRIMARY KEY,
    CandidateId    int            NOT NULL CONSTRAINT FK_RuleEvidence_Candidate REFERENCES [${schema}].RuleCandidate (CandidateId) ON DELETE CASCADE,
    SeenAt         datetime2(0)   NOT NULL CONSTRAINT DF_RuleEvidence_SeenAt DEFAULT SYSUTCDATETIME(),
    Application    nvarchar(200)  NULL,
    Component      nvarchar(200)  NULL,
    RepositoryUrl  nvarchar(400)  NULL,
    SourceCommit   nvarchar(64)   NULL,
    Stage          nvarchar(20)   NULL,             -- build or run: where the failure behind it happened
    Outcome        nvarchar(40)   NULL,             -- verification status of the component (ok, finding, ...)
    ExitReason     nvarchar(2000) NULL,             -- the attempts: failure rule, exit code, diagnosis
    LogExcerpt     nvarchar(max)  NULL,             -- tail of the failing build or run log
    Model          nvarchar(200)  NULL,
    AttemptsJson   nvarchar(max)  NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_RuleEvidence_Candidate' AND object_id = OBJECT_ID(N'[${schema}].RuleEvidence'))
CREATE INDEX IX_RuleEvidence_Candidate ON [${schema}].RuleEvidence (CandidateId, SeenAt DESC);
GO

CREATE OR ALTER PROCEDURE [${schema}].ProposeRuleCandidate
    @Kind nvarchar(20), @Fingerprint char(64), @RuleId nvarchar(200), @Title nvarchar(400), @Source nvarchar(40),
    @TargetFile nvarchar(200), @RuleYaml nvarchar(max), @Diff nvarchar(max), @Confidence decimal(4,2),
    @Model nvarchar(200), @LearnedFrom nvarchar(400),
    @Application nvarchar(200), @Component nvarchar(200), @RepositoryUrl nvarchar(400), @SourceCommit nvarchar(64),
    @Stage nvarchar(20), @Outcome nvarchar(40), @ExitReason nvarchar(2000), @LogExcerpt nvarchar(max),
    @EvidenceModel nvarchar(200), @AttemptsJson nvarchar(max)
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @id int, @status nvarchar(20), @result nvarchar(20);
    BEGIN TRANSACTION;
    SELECT @id = CandidateId, @status = Status FROM [${schema}].RuleCandidate WITH (UPDLOCK, HOLDLOCK)
    WHERE Fingerprint = @Fingerprint;
    IF @id IS NULL
    BEGIN
        INSERT [${schema}].RuleCandidate (Kind, Fingerprint, RuleId, Title, Source, TargetFile, RuleYaml, Diff, Confidence,
                                          Model, LearnedFrom)
        VALUES (@Kind, @Fingerprint, @RuleId, @Title, @Source, @TargetFile, @RuleYaml, @Diff, @Confidence, @Model, @LearnedFrom);
        SET @id = CAST(SCOPE_IDENTITY() AS int);
        SET @result = N'new';
    END
    ELSE IF @status = N'pending'
    BEGIN
        UPDATE [${schema}].RuleCandidate SET SeenCount = SeenCount + 1, LastSeenAt = SYSUTCDATETIME(),
               Confidence = CASE WHEN @Confidence > Confidence THEN @Confidence ELSE Confidence END
        WHERE CandidateId = @id;
        SET @result = N'seen';
    END
    ELSE
        SET @result = @status;           -- rejected: remembered and not proposed again; approved: in the ruleset
    IF @result IN (N'new', N'seen')
    BEGIN
        INSERT [${schema}].RuleEvidence (CandidateId, Application, Component, RepositoryUrl, SourceCommit, Stage, Outcome,
                                         ExitReason, LogExcerpt, Model, AttemptsJson)
        VALUES (@id, @Application, @Component, @RepositoryUrl, @SourceCommit, @Stage, @Outcome, @ExitReason, @LogExcerpt,
                @EvidenceModel, @AttemptsJson);
        DELETE [${schema}].RuleEvidence WHERE CandidateId = @id AND EvidenceId NOT IN
            (SELECT TOP (20) EvidenceId FROM [${schema}].RuleEvidence WHERE CandidateId = @id ORDER BY EvidenceId DESC);
    END
    COMMIT TRANSACTION;
    SELECT @id AS CandidateId, @result AS Result;
END;
GO

-- Audit trail: one row per changed row of BusinessUnit, Product and Application (mapping and the
-- people-maintained columns; routine LastSeenAt updates by the scan are not logged). Written by
-- triggers, so changes made directly with SQL are recorded too. Who: the admin UI and the API set the
-- signed-in user or API client in SESSION_CONTEXT (read-only for the connection); otherwise it is the
-- database login.
-- DbLogin is always the real database login. Nobody is granted UPDATE or DELETE on this table.
IF OBJECT_ID(N'[${schema}].AuditLog', N'U') IS NULL
CREATE TABLE [${schema}].AuditLog (
    AuditId       bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_AuditLog PRIMARY KEY,
    ChangedAt     datetime2(3)  NOT NULL CONSTRAINT DF_AuditLog_ChangedAt DEFAULT SYSUTCDATETIME(),
    ChangedBy     nvarchar(256) NOT NULL,          -- user (e-mail / UPN) or database login
    ChangedByName nvarchar(256) NULL,              -- display name from the sign-in
    DbLogin       nvarchar(256) NOT NULL CONSTRAINT DF_AuditLog_DbLogin DEFAULT ORIGINAL_LOGIN(),
    Via           nvarchar(20)  NOT NULL,          -- admin UI, API, scan, SQL
    TableName     nvarchar(50)  NOT NULL,
    RowId         int           NOT NULL,
    RowName       nvarchar(200) NULL,
    Action        nvarchar(10)  NOT NULL,          -- insert, update, delete
    OldValues     nvarchar(max) NULL,              -- JSON
    NewValues     nvarchar(max) NULL               -- JSON
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AuditLog_ChangedAt' AND object_id = OBJECT_ID(N'[${schema}].AuditLog'))
CREATE INDEX IX_AuditLog_ChangedAt ON [${schema}].AuditLog (ChangedAt DESC) INCLUDE (TableName, RowId);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AuditLog_Row' AND object_id = OBJECT_ID(N'[${schema}].AuditLog'))
CREATE INDEX IX_AuditLog_Row ON [${schema}].AuditLog (TableName, RowId, ChangedAt DESC);
GO

-- Access log (optional, CONTAINERIZER_VIEW_AUDIT=true): who signed in to the web UI and which results
-- pages they opened. Written by the web UI through its admin login; nobody is granted UPDATE or DELETE.
IF OBJECT_ID(N'[${schema}].AccessLog', N'U') IS NULL
CREATE TABLE [${schema}].AccessLog (
    AccessId      bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_AccessLog PRIMARY KEY,
    At            datetime2(3)  NOT NULL CONSTRAINT DF_AccessLog_At DEFAULT SYSUTCDATETIME(),
    UserName      nvarchar(256) NOT NULL,          -- e-mail / UPN, or sub:<subject id>
    DisplayName   nvarchar(256) NULL,
    Event         nvarchar(20)  NOT NULL,          -- sign-in, sign-in refused, sign-out, view
    Path          nvarchar(400) NULL,              -- page opened (no query string except the business unit filter)
    ApplicationId int           NULL,              -- the application whose page was opened
    ClientAddress nvarchar(64)  NULL,              -- address the request came from (a proxy, if there is one)
    DbLogin       nvarchar(256) NOT NULL CONSTRAINT DF_AccessLog_DbLogin DEFAULT ORIGINAL_LOGIN()
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AccessLog_At' AND object_id = OBJECT_ID(N'[${schema}].AccessLog'))
CREATE INDEX IX_AccessLog_At ON [${schema}].AccessLog (At DESC) INCLUDE (UserName, Event, ApplicationId);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_AccessLog_User' AND object_id = OBJECT_ID(N'[${schema}].AccessLog'))
CREATE INDEX IX_AccessLog_User ON [${schema}].AccessLog (UserName, At DESC);
GO

CREATE OR ALTER FUNCTION [${schema}].fnAuditWho()
RETURNS TABLE AS RETURN
SELECT COALESCE(CAST(SESSION_CONTEXT(N'containerizer.user') AS nvarchar(256)), ORIGINAL_LOGIN()) AS ChangedBy,
       CAST(SESSION_CONTEXT(N'containerizer.user_name') AS nvarchar(256)) AS ChangedByName,
       CASE WHEN SESSION_CONTEXT(N'containerizer.user') IS NOT NULL
                 THEN COALESCE(CAST(SESSION_CONTEXT(N'containerizer.via') AS nvarchar(20)), N'admin UI')
            WHEN IS_ROLEMEMBER(N'${schema}_writer') = 1 AND IS_ROLEMEMBER(N'db_owner') = 0 THEN N'scan'
            ELSE N'SQL' END AS Via;
GO

CREATE OR ALTER TRIGGER [${schema}].trBusinessUnitAudit ON [${schema}].BusinessUnit
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'BusinessUnit', COALESCE(i.BusinessUnitId, d.BusinessUnitId),
           COALESCE(i.Name, d.Name),
           CASE WHEN d.BusinessUnitId IS NULL THEN N'insert' WHEN i.BusinessUnitId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.BusinessUnitId IS NOT NULL THEN (SELECT d.Name, d.Description, d.Owner FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.BusinessUnitId IS NOT NULL THEN (SELECT i.Name, i.Description, i.Owner FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.BusinessUnitId = i.BusinessUnitId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.BusinessUnitId IS NULL OR i.BusinessUnitId IS NULL
       OR EXISTS (SELECT i.Name, i.Description, i.Owner EXCEPT SELECT d.Name, d.Description, d.Owner);
END;
GO

CREATE OR ALTER TRIGGER [${schema}].trProductAudit ON [${schema}].Product
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'Product', COALESCE(i.ProductId, d.ProductId), COALESCE(i.Name, d.Name),
           CASE WHEN d.ProductId IS NULL THEN N'insert' WHEN i.ProductId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.ProductId IS NOT NULL THEN (SELECT d.Name, d.Description, d.Owner, d.InfoUrl,
                (SELECT b.Name FROM [${schema}].BusinessUnit b WHERE b.BusinessUnitId = d.BusinessUnitId) AS BusinessUnit
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.ProductId IS NOT NULL THEN (SELECT i.Name, i.Description, i.Owner, i.InfoUrl,
                (SELECT b.Name FROM [${schema}].BusinessUnit b WHERE b.BusinessUnitId = i.BusinessUnitId) AS BusinessUnit
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.ProductId = i.ProductId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.ProductId IS NULL OR i.ProductId IS NULL
       OR EXISTS (SELECT i.Name, i.Description, i.Owner, i.InfoUrl, i.BusinessUnitId
                  EXCEPT SELECT d.Name, d.Description, d.Owner, d.InfoUrl, d.BusinessUnitId);
END;
GO

CREATE OR ALTER TRIGGER [${schema}].trApplicationAudit ON [${schema}].Application
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'Application', COALESCE(i.ApplicationId, d.ApplicationId),
           COALESCE(i.DisplayName, i.Name, d.DisplayName, d.Name),
           CASE WHEN d.ApplicationId IS NULL THEN N'insert' WHEN i.ApplicationId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.ApplicationId IS NOT NULL THEN (SELECT d.Name, d.DisplayName, d.Description, d.Owner, d.Retired,
                (SELECT p.Name FROM [${schema}].Product p WHERE p.ProductId = d.ProductId) AS Product
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.ApplicationId IS NOT NULL THEN (SELECT i.Name, i.DisplayName, i.Description, i.Owner, i.Retired,
                (SELECT p.Name FROM [${schema}].Product p WHERE p.ProductId = i.ProductId) AS Product
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.ApplicationId = i.ApplicationId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.ApplicationId IS NULL OR i.ApplicationId IS NULL
       OR EXISTS (SELECT i.Name, i.DisplayName, i.Description, i.Owner, i.Retired, i.ProductId
                  EXCEPT SELECT d.Name, d.DisplayName, d.Description, d.Owner, d.Retired, d.ProductId);
END;
GO

-- Rule review decisions (and new candidates) in the change history; SeenCount and claims are not logged.
CREATE OR ALTER TRIGGER [${schema}].trRuleCandidateAudit ON [${schema}].RuleCandidate
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'RuleCandidate', COALESCE(i.CandidateId, d.CandidateId),
           LEFT(COALESCE(i.RuleId, d.RuleId), 200),
           CASE WHEN d.CandidateId IS NULL THEN N'insert' WHEN i.CandidateId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.CandidateId IS NOT NULL THEN (SELECT d.Kind, d.Title, d.Status, d.ReviewNote, d.AppliedAs, d.PullRequestUrl
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.CandidateId IS NOT NULL THEN (SELECT i.Kind, i.Title, i.Status, i.ReviewNote, i.AppliedAs, i.PullRequestUrl,
                CAST(CASE WHEN i.FinalYaml IS NOT NULL AND i.FinalYaml <> i.RuleYaml THEN 1 ELSE 0 END AS bit) AS Edited
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.CandidateId = i.CandidateId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.CandidateId IS NULL OR i.CandidateId IS NULL
       OR EXISTS (SELECT i.Status, i.ReviewNote, i.AppliedAs, i.PullRequestUrl
                  EXCEPT SELECT d.Status, d.ReviewNote, d.AppliedAs, d.PullRequestUrl);
END;
GO

-- Least-privilege roles. Add database users to them (docs/results-database.md):
--   ${schema}_writer: the scanner; inserts results, never touches the people-maintained columns
--   ${schema}_reader: the web UI and report readers; views and lookup tables only
--   ${schema}_admin: the admin pages of the web UI (and people editing with SQL): business units,
--                    products, the application mapping, the rule review; reads the audit log; also a reader
IF DATABASE_PRINCIPAL_ID(N'${schema}_writer') IS NULL CREATE ROLE [${schema}_writer];
IF DATABASE_PRINCIPAL_ID(N'${schema}_reader') IS NULL CREATE ROLE [${schema}_reader];
IF DATABASE_PRINCIPAL_ID(N'${schema}_admin') IS NULL CREATE ROLE [${schema}_admin];
GO
GRANT SELECT ON [${schema}].Rating TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].ApplicationAssessment TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].ComponentAssessment TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].Finding TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].ComponentMigration TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].Application TO [${schema}_writer];
GRANT UPDATE ON [${schema}].Application (Name, RepositoryUrl, SourcePath, LastSeenAt) TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].Component TO [${schema}_writer];
GRANT UPDATE ON [${schema}].Component (Name, LastSeenAt) TO [${schema}_writer];
GRANT SELECT ON [${schema}].SchemaVersion TO [${schema}_writer];
GRANT EXECUTE ON [${schema}].ProposeRuleCandidate TO [${schema}_writer];

GRANT SELECT ON [${schema}].vApplicationLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vComponentLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vFindingLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vComponentMigrationLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vUnmapped TO [${schema}_reader];
GRANT SELECT ON [${schema}].vAssessmentHistory TO [${schema}_reader];
GRANT SELECT ON [${schema}].Rating TO [${schema}_reader];
GRANT SELECT ON [${schema}].BusinessUnit TO [${schema}_reader];
GRANT SELECT ON [${schema}].Product TO [${schema}_reader];
GRANT SELECT ON [${schema}].ApplicationAssessment (AssessmentId, ApplicationId, AssessedAt, Rating, Score, EffortDays, Confidence, Verified) TO [${schema}_reader];

GRANT SELECT, INSERT, UPDATE, DELETE ON [${schema}].BusinessUnit TO [${schema}_admin];
GRANT SELECT, INSERT, UPDATE, DELETE ON [${schema}].Product TO [${schema}_admin];
GRANT SELECT ON [${schema}].Application TO [${schema}_admin];
GRANT UPDATE ON [${schema}].Application (ProductId, DisplayName, Description, Owner, Retired) TO [${schema}_admin];
GRANT SELECT ON [${schema}].AuditLog TO [${schema}_admin];
GRANT SELECT, INSERT ON [${schema}].AccessLog TO [${schema}_admin];
GRANT SELECT ON [${schema}].RuleCandidate TO [${schema}_admin];
GRANT UPDATE ON [${schema}].RuleCandidate (Status, ReviewedBy, ReviewedByName, ReviewedAt, ReviewNote, FinalYaml, AppliedAs,
                                           PullRequestUrl, ClaimedBy, ClaimedAt) TO [${schema}_admin];
GRANT SELECT ON [${schema}].RuleEvidence TO [${schema}_admin];
IF IS_ROLEMEMBER(N'${schema}_reader', N'${schema}_admin') = 0 ALTER ROLE [${schema}_reader] ADD MEMBER [${schema}_admin];
GO

IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 2) INSERT [${schema}].SchemaVersion (Version) VALUES (2);
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 3) INSERT [${schema}].SchemaVersion (Version) VALUES (3);
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 4) INSERT [${schema}].SchemaVersion (Version) VALUES (4);
-- 6: rule review (RuleCandidate, RuleEvidence); 5 is the scheduled organization scans
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 6) INSERT [${schema}].SchemaVersion (Version) VALUES (6);
GO
