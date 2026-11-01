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
--   Application 1-* SandboxCheck                                              (sandbox cluster health)
--   AuditLog: every change to BusinessUnit, Product and the mapping of Application, with who made it
--   AccessLog: who signed in to the web UI and what they looked at (optional)
--   OrgScan 1-* OrgScanRun, OrgProject, OrgRepository                        (scheduled organization scans)
--   Application 0-1 DevDatabase                                              (dev database backup for the sandbox)
--   RuleCandidate 1-* RuleEvidence: rules the learning loop learned, waiting for review (rule review)
--   SourceCredential: read-only tokens of the organizations scans may read, write tokens of output repositories
--
-- The scan fills Application, Component and the assessment tables. People maintain business units,
-- products and the application mapping in the admin pages of the web UI; a scan never overwrites them.
-- The appliance creates and upgrades it at start (docs/appliance.md).

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
-- replacements (PlanJson) and a self-contained prompt for an AI coding agent.
IF OBJECT_ID(N'[${schema}].ComponentMigration', N'U') IS NULL
CREATE TABLE [${schema}].ComponentMigration (
    AssessmentId  int            NOT NULL,
    ComponentId   int            NOT NULL,
    Outcome       nvarchar(40)   NOT NULL,         -- linux-container, partial, stays-on-windows
    ItemCount     int            NOT NULL,
    PlanJson      nvarchar(max)  NOT NULL,         -- items: replace, with, kind, packages, steps, verify, refs, findings
    AgentPrompt   nvarchar(max)  NULL,             -- NULL when nothing in the component can be changed
    CONSTRAINT PK_ComponentMigration PRIMARY KEY (AssessmentId, ComponentId),
    CONSTRAINT FK_ComponentMigration_ComponentAssessment FOREIGN KEY (AssessmentId, ComponentId)
        REFERENCES [${schema}].ComponentAssessment (AssessmentId, ComponentId) ON DELETE CASCADE
);
GO

-- What the sandbox cluster showed after Argo CD / Flux deployed a component (`containerizer org
-- --verify-sandbox`, `containerizer sandbox verify`). One row per component and check; history is kept.
-- Status: healthy, failing, pending, scheduled, not-found, error. LogTail is a redacted tail of the
-- failing container's log: the scanner writes it, the reader role cannot read it (only the view).
IF OBJECT_ID(N'[${schema}].SandboxCheck', N'U') IS NULL
CREATE TABLE [${schema}].SandboxCheck (
    CheckId       bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_SandboxCheck PRIMARY KEY,
    ApplicationId int            NOT NULL CONSTRAINT FK_SandboxCheck_Application REFERENCES [${schema}].Application (ApplicationId),
    ComponentId   int            NULL CONSTRAINT FK_SandboxCheck_Component REFERENCES [${schema}].Component (ComponentId),
    CheckedAt     datetime2(0)   NOT NULL CONSTRAINT DF_SandboxCheck_CheckedAt DEFAULT SYSUTCDATETIME(),
    Status        nvarchar(20)   NOT NULL,
    Reason        nvarchar(2000) NULL,             -- why not healthy, or "2/2 ready"
    GitOps        nvarchar(20)   NULL,             -- argocd, flux
    Namespace     nvarchar(63)   NOT NULL,
    Workloads     nvarchar(400)  NULL,             -- Deployment/web, CronJob/report, ...
    ImageRef      nvarchar(400)  NULL,
    Revision      nvarchar(64)   NULL,             -- output repository commit that was checked
    Ready         nvarchar(20)   NULL,             -- ready/desired replicas
    Restarts      int            NULL,
    RuleId        nvarchar(200)  NULL,             -- failure rule that explained it (rules/50-failures.yaml)
    Outcome       nvarchar(20)   NULL,             -- environment, external, code, platform, retry
    Diagnosis     nvarchar(2000) NULL,
    Events        nvarchar(max)  NULL,             -- JSON: recent Warning events (reason, message, count)
    LogTail       nvarchar(max)  NULL              -- redacted; not granted to the reader role
);
GO
-- 11: the component's public HTTPS URL (Sandbox HTTPS, docs/sandbox-https.md) and what opening it gave
IF COL_LENGTH(N'[${schema}].SandboxCheck', N'Url') IS NULL
    ALTER TABLE [${schema}].SandboxCheck ADD Url nvarchar(300) NULL, UrlCheck nvarchar(300) NULL;
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_SandboxCheck_Component' AND object_id = OBJECT_ID(N'[${schema}].SandboxCheck'))
CREATE INDEX IX_SandboxCheck_Component ON [${schema}].SandboxCheck (ApplicationId, ComponentId, CheckedAt DESC, CheckId DESC);
GO

-- How the generator pointed a component at the sandbox identity provider (`containerizer org` with a
-- sandbox domain, docs/sandbox-idp.md): one row per component, protocol and run. Nothing secret: client
-- ids, URLs and the names of the settings that were overridden.
IF OBJECT_ID(N'[${schema}].SandboxIdpClient', N'U') IS NULL
CREATE TABLE [${schema}].SandboxIdpClient (
    ClientRowId   bigint IDENTITY(1,1) NOT NULL CONSTRAINT PK_SandboxIdpClient PRIMARY KEY,
    AssessmentId  int            NOT NULL CONSTRAINT FK_SandboxIdpClient_Assessment REFERENCES [${schema}].ApplicationAssessment (AssessmentId) ON DELETE CASCADE,
    ComponentId   int            NOT NULL CONSTRAINT FK_SandboxIdpClient_Component REFERENCES [${schema}].Component (ComponentId),
    WrittenAt     datetime2(0)   NOT NULL CONSTRAINT DF_SandboxIdpClient_WrittenAt DEFAULT SYSUTCDATETIME(),
    Protocol      nvarchar(10)   NOT NULL,          -- oidc, wsfed, saml, none (could not be registered: Notes)
    IdpUrl        nvarchar(300)  NOT NULL,          -- https://containerizer-idp.<domain>
    AppUrl        nvarchar(300)  NULL,
    Identifier    nvarchar(400)  NULL,              -- OIDC client id, WS-Fed realm, SAML entity id
    MetadataUrl   nvarchar(400)  NULL,
    Settings      nvarchar(max)  NULL,              -- JSON: overridden settings (name -> value) and the secret's name
    Notes         nvarchar(2000) NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_SandboxIdpClient_Assessment' AND object_id = OBJECT_ID(N'[${schema}].SandboxIdpClient'))
CREATE INDEX IX_SandboxIdpClient_Assessment ON [${schema}].SandboxIdpClient (AssessmentId, ComponentId);
GO

MERGE [${schema}].Rating AS t
USING (VALUES
    ('A', N'Container-ready', N'Modern stack, containers with configuration only, no code changes', 1),
    ('B', N'Minor refactoring', N'Small code changes', 2),
    ('C', N'Major refactoring', N'Framework port needed', 3),
    ('D', N'Partial', N'Some components must stay on Windows', 4),
    ('E', N'Not feasible', N'Core depends on Windows-only technology', 5)
) AS s (Rating, Title, Description, SortOrder)
ON t.Rating = s.Rating
WHEN MATCHED THEN UPDATE SET Title = s.Title, Description = s.Description, SortOrder = s.SortOrder
WHEN NOT MATCHED THEN INSERT (Rating, Title, Description, SortOrder) VALUES (s.Rating, s.Title, s.Description, s.SortOrder);
GO

-- 16: work estimates are gone (they said little once AI coding agents do the migration work); drop
-- the EffortDays columns of databases created before. The views below are recreated without them.
IF COL_LENGTH(N'[${schema}].ApplicationAssessment', N'EffortDays') IS NOT NULL
    ALTER TABLE [${schema}].ApplicationAssessment DROP COLUMN EffortDays;
IF COL_LENGTH(N'[${schema}].ComponentAssessment', N'EffortDays') IS NOT NULL
    ALTER TABLE [${schema}].ComponentAssessment DROP COLUMN EffortDays;
IF COL_LENGTH(N'[${schema}].Finding', N'EffortDays') IS NOT NULL
    ALTER TABLE [${schema}].Finding DROP COLUMN EffortDays;
IF COL_LENGTH(N'[${schema}].ComponentMigration', N'EffortDays') IS NOT NULL
    ALTER TABLE [${schema}].ComponentMigration DROP COLUMN EffortDays;
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
-- The role the change was made in (admin, operator, product owner, API client), from the same
-- read-only SESSION_CONTEXT as the user; NULL for scans and direct SQL.
IF COL_LENGTH(N'[${schema}].AuditLog', N'ChangedByRole') IS NULL
ALTER TABLE [${schema}].AuditLog ADD ChangedByRole nvarchar(40) NULL
    CONSTRAINT DF_AuditLog_ChangedByRole DEFAULT CAST(SESSION_CONTEXT(N'containerizer.role') AS nvarchar(40));
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

-- Dev database backups operators upload for the sandbox (one per application). The file itself is
-- stored by the web UI in CONTAINERIZER_DEV_DB_DIR under StoredAs (named by its SHA-256); the scan
-- restores it into a database next to the application in the sandbox, and sets the application's
-- connection settings following Prompt. Changes are in AuditLog (the prompt is not copied there).
IF OBJECT_ID(N'[${schema}].DevDatabase', N'U') IS NULL
CREATE TABLE [${schema}].DevDatabase (
    DevDatabaseId int IDENTITY(1,1) NOT NULL CONSTRAINT PK_DevDatabase PRIMARY KEY,
    ApplicationId int            NOT NULL CONSTRAINT FK_DevDatabase_Application REFERENCES [${schema}].Application (ApplicationId)
                                 CONSTRAINT UQ_DevDatabase_Application UNIQUE,
    Engine        nvarchar(20)   NOT NULL CONSTRAINT CK_DevDatabase_Engine CHECK (Engine IN (N'sqlserver', N'postgres', N'mysql')),
    DatabaseName  nvarchar(128)  NOT NULL,
    FileName      nvarchar(200)  NOT NULL,       -- as uploaded
    SizeBytes     bigint         NOT NULL,
    Sha256        char(64)       NOT NULL,
    StoredAs      nvarchar(100)  NOT NULL,       -- <sha256>.<bak|dump|sql|sql.gz>
    Prompt        nvarchar(max)  NULL,           -- how to point the application at the database
    UploadedAt    datetime2(0)   NOT NULL CONSTRAINT DF_DevDatabase_UploadedAt DEFAULT SYSUTCDATETIME(),
    UploadedBy    nvarchar(256)  NOT NULL
);
GO
-- 14: PostgreSQL and MySQL backups too (databases made before allow SQL Server only)
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = N'CK_DevDatabase_Engine'
           AND parent_object_id = OBJECT_ID(N'[${schema}].DevDatabase') AND definition NOT LIKE N'%mysql%')
    ALTER TABLE [${schema}].DevDatabase DROP CONSTRAINT CK_DevDatabase_Engine;
GO
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = N'CK_DevDatabase_Engine'
               AND parent_object_id = OBJECT_ID(N'[${schema}].DevDatabase'))
    ALTER TABLE [${schema}].DevDatabase ADD CONSTRAINT CK_DevDatabase_Engine CHECK (Engine IN (N'sqlserver', N'postgres', N'mysql'));
GO

-- Lab services the appliance runs in its sandbox cluster for the scanned apps (labservices.py,
-- docs/lab-services.md): on or off, set by administrators on Admin -> Lab services. The system agent
-- applies the switches; this table is what the page shows and, through its trigger, the change history.
IF OBJECT_ID(N'[${schema}].LabService', N'U') IS NULL
CREATE TABLE [${schema}].LabService (
    LabServiceId  int IDENTITY(1,1) NOT NULL CONSTRAINT PK_LabService PRIMARY KEY,
    Name          nvarchar(20)   NOT NULL CONSTRAINT UQ_LabService_Name UNIQUE,
    Title         nvarchar(100)  NOT NULL,
    Enabled       bit            NOT NULL,
    Note          nvarchar(400)  NULL,           -- why, from the administrator
    ChangedAt     datetime2(0)   NOT NULL CONSTRAINT DF_LabService_ChangedAt DEFAULT SYSUTCDATETIME()
);
GO
-- the services and their defaults (SQL Server was already there for dev database restores)
INSERT [${schema}].LabService (Name, Title, Enabled)
SELECT v.Name, v.Title, v.Enabled
FROM (VALUES (N'sqlserver', N'SQL Server', 1), (N'postgres', N'PostgreSQL', 0), (N'redis', N'Redis', 0),
             (N's3', N'S3 object storage', 0), (N'azure-blob', N'Azure Blob storage', 0), (N'mysql', N'MySQL', 0),
             (N'mongodb', N'MongoDB', 0), (N'rabbitmq', N'RabbitMQ', 0), (N'kafka', N'Kafka', 0), (N'sftp', N'SFTP', 0)
     ) v (Name, Title, Enabled)
WHERE NOT EXISTS (SELECT 1 FROM [${schema}].LabService x WHERE x.Name = v.Name);
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

-- Organization scans (`containerizer worker`, docs/scheduled-scans.md). Administrators define them on the
-- admin pages: which organization, where the results go, and when to run. Tokens are never stored here:
-- they are in SourceCredential, matched by organization and output repository URL. TokenEnv and
-- OutputTokenEnv are no longer used (kept for older databases). The worker sets NextRunAt.
IF OBJECT_ID(N'[${schema}].OrgScan', N'U') IS NULL
CREATE TABLE [${schema}].OrgScan (
    ScanId          int IDENTITY(1,1) NOT NULL CONSTRAINT PK_OrgScan PRIMARY KEY,
    Name            nvarchar(200) NOT NULL CONSTRAINT UQ_OrgScan_Name UNIQUE,
    Provider        nvarchar(20)  NOT NULL CONSTRAINT CK_OrgScan_Provider CHECK (Provider IN (N'azure-devops', N'github', N'gitlab')),
    Organization    nvarchar(200) NOT NULL,
    ApiUrl          nvarchar(400) NULL CONSTRAINT CK_OrgScan_ApiUrl CHECK (ApiUrl LIKE N'https://_%' AND ApiUrl NOT LIKE N'%[<>"'' ]%'),
    TokenEnv        nvarchar(64)  NULL,
    Registry        nvarchar(400) NOT NULL,
    OutputRepo      nvarchar(400) NULL CONSTRAINT CK_OrgScan_OutputRepo CHECK (OutputRepo LIKE N'https://_%' AND OutputRepo NOT LIKE N'%[<>"'' ]%'),
    OutputBranch    nvarchar(200) NOT NULL CONSTRAINT DF_OrgScan_OutputBranch DEFAULT N'main',
    OutputTokenEnv  nvarchar(64)  NULL,
    ImagePullSecret nvarchar(253) NULL,
    IncludeRegex    nvarchar(400) NULL,
    ExcludeRegex    nvarchar(400) NULL,
    SkipForks       bit NOT NULL CONSTRAINT DF_OrgScan_SkipForks DEFAULT 1,
    StaleDays       int NOT NULL CONSTRAINT DF_OrgScan_StaleDays DEFAULT 183 CONSTRAINT CK_OrgScan_StaleDays CHECK (StaleDays BETWEEN 0 AND 3650),
    Verify          bit NOT NULL CONSTRAINT DF_OrgScan_Verify DEFAULT 1,
    Gate            bit NOT NULL CONSTRAINT DF_OrgScan_Gate DEFAULT 1,
    PushImages      bit NOT NULL CONSTRAINT DF_OrgScan_PushImages DEFAULT 1,
    UseAi           bit NOT NULL CONSTRAINT DF_OrgScan_UseAi DEFAULT 0,
    ScheduleDays    tinyint  NOT NULL CONSTRAINT DF_OrgScan_ScheduleDays DEFAULT 0 CONSTRAINT CK_OrgScan_ScheduleDays CHECK (ScheduleDays BETWEEN 0 AND 127),  -- Mon=1, Tue=2, ... Sun=64; 0: on demand only
    ScheduleMinute  smallint NOT NULL CONSTRAINT DF_OrgScan_ScheduleMinute DEFAULT 120 CONSTRAINT CK_OrgScan_ScheduleMinute CHECK (ScheduleMinute BETWEEN 0 AND 1439),  -- minutes after midnight UTC
    Enabled         bit NOT NULL CONSTRAINT DF_OrgScan_Enabled DEFAULT 1,
    NextRunAt       datetime2(0) NULL,
    CreatedAt       datetime2(0) NOT NULL CONSTRAINT DF_OrgScan_CreatedAt DEFAULT SYSUTCDATETIME()
);
GO
-- LLM-heavy mode (platform migrations and the sandbox tester ask the LLM as often as they need); also needs
-- UseAi and CONTAINERIZER_LLM_HEAVY on the worker (appliance.env CZ_LLM_HEAVY), off by default
IF COL_LENGTH(N'[${schema}].OrgScan', N'LlmHeavy') IS NULL
ALTER TABLE [${schema}].OrgScan ADD LlmHeavy bit NOT NULL CONSTRAINT DF_OrgScan_LlmHeavy DEFAULT 0;
GO
-- 19: how the scan asks the LLM: 'inline' (during the scan) or 'queued' (rules only during the scan; the
-- component reviews wait in the LLM queue, LlmJob, and their answers apply at the next scan)
IF COL_LENGTH(N'[${schema}].OrgScan', N'LlmMode') IS NULL
ALTER TABLE [${schema}].OrgScan ADD LlmMode nvarchar(10) NOT NULL CONSTRAINT DF_OrgScan_LlmMode DEFAULT N'inline'
    CONSTRAINT CK_OrgScan_LlmMode CHECK (LlmMode IN (N'inline', N'queued'));
GO

-- One row per run of an organization scan: queued on schedule or with "Run now", claimed by a worker.
IF OBJECT_ID(N'[${schema}].OrgScanRun', N'U') IS NULL
CREATE TABLE [${schema}].OrgScanRun (
    RunId           int IDENTITY(1,1) NOT NULL CONSTRAINT PK_OrgScanRun PRIMARY KEY,
    ScanId          int NOT NULL CONSTRAINT FK_OrgScanRun_Scan REFERENCES [${schema}].OrgScan (ScanId),
    TriggeredBy     nvarchar(20)  NOT NULL CONSTRAINT CK_OrgScanRun_Trigger CHECK (TriggeredBy IN (N'schedule', N'manual')),
    RequestedBy     nvarchar(256) NULL,                 -- who pressed "Run now"
    RequestedAt     datetime2(0)  NOT NULL CONSTRAINT DF_OrgScanRun_RequestedAt DEFAULT SYSUTCDATETIME(),
    Status          nvarchar(20)  NOT NULL CONSTRAINT DF_OrgScanRun_Status DEFAULT N'queued'
                    CONSTRAINT CK_OrgScanRun_Status CHECK (Status IN (N'queued', N'running', N'succeeded', N'failed', N'cancelled')),
    CancelRequested bit NOT NULL CONSTRAINT DF_OrgScanRun_Cancel DEFAULT 0,
    CancelledBy     nvarchar(256) NULL,
    Worker          nvarchar(256) NULL,
    StartedAt       datetime2(0)  NULL,
    HeartbeatAt     datetime2(0)  NULL,
    FinishedAt      datetime2(0)  NULL,
    ImageTag        nvarchar(64)  NULL,
    ReposListed     int NULL,
    ReposTotal      int NULL,                           -- to process (after filters)
    ReposDone       int NULL,
    ReposNew        int NULL,                           -- found for the first time in this run
    ReposDeployed   int NULL,
    ReposSkipped    int NULL,
    ReposErrors     int NULL,
    CurrentRepo     nvarchar(400) NULL,
    Message         nvarchar(2000) NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_OrgScanRun_Scan' AND object_id = OBJECT_ID(N'[${schema}].OrgScanRun'))
CREATE INDEX IX_OrgScanRun_Scan ON [${schema}].OrgScanRun (ScanId, RunId DESC) INCLUDE (Status);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_OrgScanRun_Status' AND object_id = OBJECT_ID(N'[${schema}].OrgScanRun'))
CREATE INDEX IX_OrgScanRun_Status ON [${schema}].OrgScanRun (Status, RunId);
GO

-- Every repository an organization scan has listed. The scan keeps it current (new repositories are
-- added, ones the provider no longer lists get RemovedAt) and records why it skipped one (SkipStatus /
-- SkipReason: Dockerfile, no application code, stale, archived, ...). People set AdminState: NULL lets
-- the scan decide, 'enabled' processes it even when an automatic skip applies, 'disabled' never does.
IF OBJECT_ID(N'[${schema}].OrgRepository', N'U') IS NULL
CREATE TABLE [${schema}].OrgRepository (
    RepositoryId    int IDENTITY(1,1) NOT NULL CONSTRAINT PK_OrgRepository PRIMARY KEY,
    ScanId          int NOT NULL CONSTRAINT FK_OrgRepository_Scan REFERENCES [${schema}].OrgScan (ScanId),
    ProjectName     nvarchar(200) NOT NULL,            -- Azure DevOps project, GitLab subgroup, or _ (none)
    Name            nvarchar(200) NOT NULL,
    ExternalId      nvarchar(100) NULL,                -- the provider's id: follows renames
    CloneUrl        nvarchar(400) NOT NULL,
    WebUrl          nvarchar(400) NULL,
    RepositoryUrl   nvarchar(400) NULL,                -- as Application.RepositoryUrl, to link the results
    DefaultBranch   nvarchar(200) NULL,
    AppName         nvarchar(63)  NULL,                -- namespace / folder name in the sandbox
    LastActivityAt  datetime2(0)  NULL,
    FirstSeenAt     datetime2(0)  NOT NULL CONSTRAINT DF_OrgRepository_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    FirstRunId      int NULL,
    LastSeenAt      datetime2(0)  NOT NULL CONSTRAINT DF_OrgRepository_LastSeenAt DEFAULT SYSUTCDATETIME(),
    RemovedAt       datetime2(0)  NULL,
    AdminState      nvarchar(10)  NULL CONSTRAINT CK_OrgRepository_AdminState CHECK (AdminState IN (N'enabled', N'disabled')),
    AdminNote       nvarchar(400) NULL,
    SkipStatus      nvarchar(40)  NULL,
    SkipReason      nvarchar(1000) NULL,
    LastStatus      nvarchar(40)  NULL,                -- deployed, no-a-components, skipped-*, disabled, error
    LastReason      nvarchar(1000) NULL,
    LastCommit      nvarchar(64)  NULL,
    LastCommitAt    datetime2(0)  NULL,
    LastRating      char(1)       NULL,
    LastScannedAt   datetime2(0)  NULL,
    LastRunId       int NULL,
    LastSeconds     decimal(9,1)  NULL,
    LastDetail      nvarchar(max) NULL,                -- JSON: deployed and excluded components, overridden skips
    Enabled AS (CAST(CASE WHEN AdminState = N'enabled' THEN 1 WHEN AdminState = N'disabled' THEN 0
                          WHEN SkipStatus IS NULL THEN 1 ELSE 0 END AS bit)),
    CONSTRAINT UQ_OrgRepository_Name UNIQUE (ScanId, ProjectName, Name)
);
GO

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_OrgRepository_Url' AND object_id = OBJECT_ID(N'[${schema}].OrgRepository'))
CREATE INDEX IX_OrgRepository_Url ON [${schema}].OrgRepository (RepositoryUrl) INCLUDE (AdminState, RemovedAt, ScanId, ProjectName);
GO

-- 17: the projects of an organization scan (Azure DevOps projects, GitLab subgroups; GitHub has none).
-- The scan adds the ones it lists and marks the ones it no longer lists. People set AdminState:
-- 'disabled' leaves every repository of the project out of the full scan and hides its results from
-- the results pages; NULL lets each repository's own setting decide.
IF OBJECT_ID(N'[${schema}].OrgProject', N'U') IS NULL
CREATE TABLE [${schema}].OrgProject (
    ProjectId       int IDENTITY(1,1) NOT NULL CONSTRAINT PK_OrgProject PRIMARY KEY,
    ScanId          int NOT NULL CONSTRAINT FK_OrgProject_Scan REFERENCES [${schema}].OrgScan (ScanId),
    Name            nvarchar(200) NOT NULL,             -- as OrgRepository.ProjectName
    FirstSeenAt     datetime2(0)  NOT NULL CONSTRAINT DF_OrgProject_FirstSeenAt DEFAULT SYSUTCDATETIME(),
    LastSeenAt      datetime2(0)  NOT NULL CONSTRAINT DF_OrgProject_LastSeenAt DEFAULT SYSUTCDATETIME(),
    RemovedAt       datetime2(0)  NULL,
    AdminState      nvarchar(10)  NULL CONSTRAINT CK_OrgProject_AdminState CHECK (AdminState IN (N'disabled')),
    AdminNote       nvarchar(400) NULL,
    CONSTRAINT UQ_OrgProject_Name UNIQUE (ScanId, Name)
);
GO

-- 17: discovery runs list the projects, repositories and latest commits only (no clone, no assessment)
IF COL_LENGTH(N'[${schema}].OrgScanRun', N'Kind') IS NULL
ALTER TABLE [${schema}].OrgScanRun ADD Kind nvarchar(20) NOT NULL CONSTRAINT DF_OrgScanRun_Kind DEFAULT N'full'
    CONSTRAINT CK_OrgScanRun_Kind CHECK (Kind IN (N'full', N'discovery'));
GO
-- 17: "Scan now" of chosen projects and repositories: JSON {"projects": [...], "repositories": ["project/name", ...]};
-- NULL: the whole organization
IF COL_LENGTH(N'[${schema}].OrgScanRun', N'Scope') IS NULL
ALTER TABLE [${schema}].OrgScanRun ADD Scope nvarchar(max) NULL CONSTRAINT CK_OrgScanRun_Scope CHECK (Scope IS NULL OR ISJSON(Scope) = 1);
GO

-- Every repository with its project's setting and whether the full scan processes it (Active): not removed,
-- not disabled by an administrator (itself or its project) and not skipped automatically, unless an
-- administrator enabled it. The admin pages read it.
CREATE OR ALTER VIEW [${schema}].vOrgRepository AS
SELECT r.RepositoryId, r.ScanId, r.ProjectName, r.Name, r.ExternalId, r.CloneUrl, r.WebUrl, r.RepositoryUrl,
       r.DefaultBranch, r.AppName, r.LastActivityAt, r.FirstSeenAt, r.FirstRunId, r.LastSeenAt, r.RemovedAt,
       r.AdminState, r.AdminNote, r.SkipStatus, r.SkipReason, r.LastStatus, r.LastReason, r.LastCommit, r.LastCommitAt,
       r.LastRating, r.LastScannedAt, r.LastRunId, r.LastSeconds, r.LastDetail, r.Enabled,
       p.ProjectId, p.AdminState AS ProjectState, p.AdminNote AS ProjectNote,
       COALESCE(r.LastCommitAt, r.LastActivityAt) AS LatestCommitAt,
       CAST(CASE WHEN r.RemovedAt IS NULL AND r.Enabled = 1 AND p.AdminState IS NULL THEN 1 ELSE 0 END AS bit) AS Active
FROM [${schema}].OrgRepository r
LEFT JOIN [${schema}].OrgProject p ON p.ScanId = r.ScanId AND p.Name = r.ProjectName;
GO

-- Repositories an administrator disabled, by themselves or through their project. Their applications
-- are left out of the results pages (the views below); the admin pages still show them.
CREATE OR ALTER VIEW [${schema}].vDisabledRepositoryUrl AS
SELECT DISTINCT r.RepositoryUrl
FROM [${schema}].OrgRepository r
LEFT JOIN [${schema}].OrgProject p ON p.ScanId = r.ScanId AND p.Name = r.ProjectName
WHERE r.RemovedAt IS NULL AND r.RepositoryUrl IS NOT NULL
  AND (r.AdminState = N'disabled' OR p.AdminState = N'disabled');
GO

-- Latest assessment of every application, with its product and business unit ("(not assigned)" when
-- nobody has mapped it yet). This is what the web UI reads. Applications people hid (Retired) and the
-- ones whose repository or project an administrator disabled for the organization scans are left out.
CREATE OR ALTER VIEW [${schema}].vApplicationLatest AS
SELECT a.ApplicationId,
       COALESCE(a.DisplayName, a.Name) AS ApplicationName,
       a.Name AS ScanName, a.Description, a.Owner, a.RepositoryUrl, a.SourcePath,
       p.ProductId, p.Name AS ProductName, p.Owner AS ProductOwner, p.InfoUrl AS ProductInfoUrl,
       bu.BusinessUnitId, bu.Name AS BusinessUnitName, bu.Owner AS BusinessUnitOwner,
       x.AssessmentId, x.AssessedAt, x.Rating, r.Title AS RatingTitle, r.Description AS RatingDescription,
       x.Score, x.Confidence, x.Summary, x.Verified, x.SourceCommit, x.SourceBranch
FROM [${schema}].Application a
CROSS APPLY (SELECT TOP (1) * FROM [${schema}].ApplicationAssessment aa
             WHERE aa.ApplicationId = a.ApplicationId
             ORDER BY aa.AssessedAt DESC, aa.AssessmentId DESC) x
JOIN [${schema}].Rating r ON r.Rating = x.Rating
LEFT JOIN [${schema}].Product p ON p.ProductId = a.ProductId
LEFT JOIN [${schema}].BusinessUnit bu ON bu.BusinessUnitId = p.BusinessUnitId
WHERE a.Retired = 0
  AND NOT EXISTS (SELECT 1 FROM [${schema}].vDisabledRepositoryUrl h WHERE h.RepositoryUrl = a.RepositoryUrl);
GO

CREATE OR ALTER VIEW [${schema}].vComponentLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.ProductName, l.BusinessUnitName, l.AssessmentId,
       c.ComponentId, c.Name AS ComponentName, c.ProjectPath,
       ca.Role, ca.Tier, ca.TargetFramework, ca.Verdict, ca.VerdictText, ca.Score,
       ca.Confidence, ca.WindowsContainerOk, ca.VerifyStatus, ca.VerifyDetail
FROM [${schema}].vApplicationLatest l
JOIN [${schema}].ComponentAssessment ca ON ca.AssessmentId = l.AssessmentId
JOIN [${schema}].Component c ON c.ComponentId = ca.ComponentId;
GO

CREATE OR ALTER VIEW [${schema}].vFindingLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.AssessmentId, f.ComponentId, c.Name AS ComponentName,
       f.FindingId, f.RuleId, f.Severity, f.RuleSeverity, f.Category, f.Title, f.Why, f.Fix,
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
       aa.AssessedAt, aa.Rating, aa.Score, aa.Verified,
       COALESCE(f.Blockers, 0) AS Blockers, COALESCE(f.Rewrites, 0) AS Rewrites
FROM [${schema}].ApplicationAssessment aa
JOIN [${schema}].Application a ON a.ApplicationId = aa.ApplicationId
LEFT JOIN [${schema}].Product p ON p.ProductId = a.ProductId
LEFT JOIN [${schema}].BusinessUnit bu ON bu.BusinessUnitId = p.BusinessUnitId
OUTER APPLY (SELECT COUNT(DISTINCT CASE WHEN x.Severity = 'blocker' THEN x.RuleId END) AS Blockers,
                    COUNT(DISTINCT CASE WHEN x.Severity = 'rewrite' THEN x.RuleId END) AS Rewrites
             FROM [${schema}].Finding x
             WHERE x.AssessmentId = aa.AssessmentId AND x.Severity IN ('blocker', 'rewrite')) f
WHERE a.Retired = 0
  AND NOT EXISTS (SELECT 1 FROM [${schema}].vDisabledRepositoryUrl h WHERE h.RepositoryUrl = a.RepositoryUrl);
GO

CREATE OR ALTER VIEW [${schema}].vComponentMigrationLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.AssessmentId, m.ComponentId, c.Name AS ComponentName, c.ProjectPath,
       m.Outcome, m.ItemCount, m.PlanJson, m.AgentPrompt
FROM [${schema}].vApplicationLatest l
JOIN [${schema}].ComponentMigration m ON m.AssessmentId = l.AssessmentId
JOIN [${schema}].Component c ON c.ComponentId = m.ComponentId;
GO

-- The latest sandbox check of every application (one row per component it had deployed then; the
-- rows of one check share CheckedAt), without the log tail. The application page reads it.
-- Sandbox IdP registrations of the latest assessment (with any) of each application. The application page reads it.
CREATE OR ALTER VIEW [${schema}].vSandboxIdpLatest AS
SELECT aa.ApplicationId, x.ComponentId, c.Name AS ComponentName, x.WrittenAt, x.Protocol, x.IdpUrl, x.AppUrl,
       x.Identifier, x.MetadataUrl, x.Settings, x.Notes
FROM [${schema}].SandboxIdpClient x
JOIN [${schema}].ApplicationAssessment aa ON aa.AssessmentId = x.AssessmentId
JOIN [${schema}].Component c ON c.ComponentId = x.ComponentId
WHERE x.AssessmentId = (SELECT MAX(y.AssessmentId) FROM [${schema}].SandboxIdpClient y
                        JOIN [${schema}].ApplicationAssessment ya ON ya.AssessmentId = y.AssessmentId
                        WHERE ya.ApplicationId = aa.ApplicationId);
GO
CREATE OR ALTER VIEW [${schema}].vSandboxLatest AS
SELECT x.ApplicationId, x.ComponentId, c.Name AS ComponentName, x.CheckedAt, x.Status, x.Reason, x.GitOps,
       x.Namespace, x.Workloads, x.ImageRef, x.Revision, x.Ready, x.Restarts, x.RuleId, x.Outcome, x.Diagnosis, x.Events,
       x.Url, x.UrlCheck
FROM (SELECT s.*, MAX(s.CheckedAt) OVER (PARTITION BY s.ApplicationId) AS LastCheck,
             ROW_NUMBER() OVER (PARTITION BY s.ApplicationId, s.ComponentId, s.CheckedAt ORDER BY s.CheckId DESC) AS n
      FROM [${schema}].SandboxCheck s) x
JOIN [${schema}].Application a ON a.ApplicationId = x.ApplicationId
LEFT JOIN [${schema}].Component c ON c.ComponentId = x.ComponentId
WHERE x.CheckedAt = x.LastCheck AND x.n = 1 AND a.Retired = 0
  AND NOT EXISTS (SELECT 1 FROM [${schema}].vDisabledRepositoryUrl h WHERE h.RepositoryUrl = a.RepositoryUrl);
GO

-- Applications nobody has mapped to a product yet, and products without a business unit.
CREATE OR ALTER VIEW [${schema}].vUnmapped AS
SELECT N'Application' AS Kind, a.ApplicationId AS Id, COALESCE(a.DisplayName, a.Name) AS Name, a.RepositoryUrl AS Detail
FROM [${schema}].Application a WHERE a.ProductId IS NULL AND a.Retired = 0
  AND NOT EXISTS (SELECT 1 FROM [${schema}].vDisabledRepositoryUrl h WHERE h.RepositoryUrl = a.RepositoryUrl)
UNION ALL
SELECT N'Product', p.ProductId, p.Name, NULL FROM [${schema}].Product p WHERE p.BusinessUnitId IS NULL;
GO

-- Queue a run of an organization scan, unless one is already queued or running. Returns the RunId
-- (0 when the scan is disabled or busy). The admin pages call it for "Run now" and "Discover", the
-- worker on schedule (always a full scan). @Kind: 'full' or 'discovery'.
CREATE OR ALTER PROCEDURE [${schema}].QueueOrgScanRun @ScanId int, @TriggeredBy nvarchar(20), @Kind nvarchar(20) = N'full',
    @Scope nvarchar(max) = NULL
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    DECLARE @id int = 0;
    BEGIN TRANSACTION;
    IF EXISTS (SELECT 1 FROM [${schema}].OrgScan WITH (UPDLOCK, HOLDLOCK) WHERE ScanId = @ScanId AND Enabled = 1)
       AND NOT EXISTS (SELECT 1 FROM [${schema}].OrgScanRun WITH (UPDLOCK, HOLDLOCK)
                       WHERE ScanId = @ScanId AND Status IN (N'queued', N'running'))
    BEGIN
        INSERT [${schema}].OrgScanRun (ScanId, TriggeredBy, RequestedBy, Kind, Scope)
        SELECT @ScanId, @TriggeredBy, CASE WHEN @TriggeredBy = N'manual' THEN w.ChangedBy END, @Kind, @Scope
        FROM [${schema}].fnAuditWho() w;
        SET @id = SCOPE_IDENTITY();
    END
    COMMIT;
    SELECT @id AS RunId;
END;
GO

-- Cancel a run: a queued one at once, a running one after the repository it is on.
CREATE OR ALTER PROCEDURE [${schema}].CancelOrgScanRun @RunId int
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @who nvarchar(256) = (SELECT ChangedBy FROM [${schema}].fnAuditWho());
    UPDATE [${schema}].OrgScanRun
    SET Status = CASE WHEN Status = N'queued' THEN N'cancelled' ELSE Status END,
        FinishedAt = CASE WHEN Status = N'queued' THEN SYSUTCDATETIME() ELSE FinishedAt END,
        CancelRequested = 1, CancelledBy = @who
    WHERE RunId = @RunId AND Status IN (N'queued', N'running');
    SELECT @@ROWCOUNT AS Cancelled;
END;
GO

CREATE OR ALTER TRIGGER [${schema}].trOrgScanAudit ON [${schema}].OrgScan
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'OrgScan', COALESCE(i.ScanId, d.ScanId), COALESCE(i.Name, d.Name),
           CASE WHEN d.ScanId IS NULL THEN N'insert' WHEN i.ScanId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.ScanId IS NOT NULL THEN (SELECT d.Name, d.Provider, d.Organization, d.ApiUrl, d.TokenEnv, d.Registry,
                d.OutputRepo, d.OutputBranch, d.OutputTokenEnv, d.ImagePullSecret, d.IncludeRegex, d.ExcludeRegex, d.SkipForks,
                d.StaleDays, d.Verify, d.Gate, d.PushImages, d.UseAi, d.LlmHeavy, d.LlmMode, d.ScheduleDays, d.ScheduleMinute, d.Enabled
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.ScanId IS NOT NULL THEN (SELECT i.Name, i.Provider, i.Organization, i.ApiUrl, i.TokenEnv, i.Registry,
                i.OutputRepo, i.OutputBranch, i.OutputTokenEnv, i.ImagePullSecret, i.IncludeRegex, i.ExcludeRegex, i.SkipForks,
                i.StaleDays, i.Verify, i.Gate, i.PushImages, i.UseAi, i.LlmHeavy, i.LlmMode, i.ScheduleDays, i.ScheduleMinute, i.Enabled
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.ScanId = i.ScanId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.ScanId IS NULL OR i.ScanId IS NULL
       OR EXISTS (SELECT i.Name, i.Provider, i.Organization, i.ApiUrl, i.TokenEnv, i.Registry, i.OutputRepo, i.OutputBranch,
                         i.OutputTokenEnv, i.ImagePullSecret, i.IncludeRegex, i.ExcludeRegex, i.SkipForks, i.StaleDays,
                         i.Verify, i.Gate, i.PushImages, i.UseAi, i.LlmHeavy, i.LlmMode, i.ScheduleDays, i.ScheduleMinute, i.Enabled
                  EXCEPT SELECT d.Name, d.Provider, d.Organization, d.ApiUrl, d.TokenEnv, d.Registry, d.OutputRepo, d.OutputBranch,
                         d.OutputTokenEnv, d.ImagePullSecret, d.IncludeRegex, d.ExcludeRegex, d.SkipForks, d.StaleDays,
                         d.Verify, d.Gate, d.PushImages, d.UseAi, d.LlmHeavy, d.LlmMode, d.ScheduleDays, d.ScheduleMinute, d.Enabled);
END;
GO

-- Repositories: found by a scan, enabled/disabled by people, automatic skips that start or stop applying,
-- and leaving the organization. Routine per-run columns (LastStatus, LastCommit, ...) are not logged.
CREATE OR ALTER TRIGGER [${schema}].trOrgRepositoryAudit ON [${schema}].OrgRepository
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'OrgRepository', COALESCE(i.RepositoryId, d.RepositoryId),
           COALESCE(CASE WHEN i.ProjectName = N'_' THEN i.Name ELSE i.ProjectName + N'/' + i.Name END,
                    CASE WHEN d.ProjectName = N'_' THEN d.Name ELSE d.ProjectName + N'/' + d.Name END),
           CASE WHEN d.RepositoryId IS NULL THEN N'insert' WHEN i.RepositoryId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.RepositoryId IS NOT NULL THEN (SELECT COALESCE(d.AdminState, N'automatic') AS Setting, d.AdminNote AS Note,
                d.SkipReason AS Skipped, CAST(CASE WHEN d.RemovedAt IS NULL THEN 0 ELSE 1 END AS bit) AS Removed,
                (SELECT s.Name FROM [${schema}].OrgScan s WHERE s.ScanId = d.ScanId) AS OrgScan
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.RepositoryId IS NOT NULL THEN (SELECT COALESCE(i.AdminState, N'automatic') AS Setting, i.AdminNote AS Note,
                i.SkipReason AS Skipped, CAST(CASE WHEN i.RemovedAt IS NULL THEN 0 ELSE 1 END AS bit) AS Removed,
                (SELECT s.Name FROM [${schema}].OrgScan s WHERE s.ScanId = i.ScanId) AS OrgScan
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.RepositoryId = i.RepositoryId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.RepositoryId IS NULL OR i.RepositoryId IS NULL
       OR EXISTS (SELECT i.AdminState, i.AdminNote, i.SkipStatus, i.SkipReason, CASE WHEN i.RemovedAt IS NULL THEN 0 ELSE 1 END,
                         i.ProjectName, i.Name
                  EXCEPT SELECT d.AdminState, d.AdminNote, d.SkipStatus, d.SkipReason, CASE WHEN d.RemovedAt IS NULL THEN 0 ELSE 1 END,
                         d.ProjectName, d.Name);
END;
GO

-- Projects: found by a scan, disabled or enabled again by people, and leaving the organization.
CREATE OR ALTER TRIGGER [${schema}].trOrgProjectAudit ON [${schema}].OrgProject
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'OrgProject', COALESCE(i.ProjectId, d.ProjectId), COALESCE(i.Name, d.Name),
           CASE WHEN d.ProjectId IS NULL THEN N'insert' WHEN i.ProjectId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.ProjectId IS NOT NULL THEN (SELECT COALESCE(d.AdminState, N'enabled') AS Setting, d.AdminNote AS Note,
                CAST(CASE WHEN d.RemovedAt IS NULL THEN 0 ELSE 1 END AS bit) AS Removed,
                (SELECT s.Name FROM [${schema}].OrgScan s WHERE s.ScanId = d.ScanId) AS OrgScan
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.ProjectId IS NOT NULL THEN (SELECT COALESCE(i.AdminState, N'enabled') AS Setting, i.AdminNote AS Note,
                CAST(CASE WHEN i.RemovedAt IS NULL THEN 0 ELSE 1 END AS bit) AS Removed,
                (SELECT s.Name FROM [${schema}].OrgScan s WHERE s.ScanId = i.ScanId) AS OrgScan
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.ProjectId = i.ProjectId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.ProjectId IS NULL OR i.ProjectId IS NULL
       OR EXISTS (SELECT i.AdminState, i.AdminNote, CASE WHEN i.RemovedAt IS NULL THEN 0 ELSE 1 END
                  EXCEPT SELECT d.AdminState, d.AdminNote, CASE WHEN d.RemovedAt IS NULL THEN 0 ELSE 1 END);
END;
GO

CREATE OR ALTER TRIGGER [${schema}].trDevDatabaseAudit ON [${schema}].DevDatabase
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'DevDatabase', COALESCE(i.ApplicationId, d.ApplicationId),
           (SELECT COALESCE(a.DisplayName, a.Name) FROM [${schema}].Application a
            WHERE a.ApplicationId = COALESCE(i.ApplicationId, d.ApplicationId)),
           CASE WHEN d.DevDatabaseId IS NULL THEN N'insert' WHEN i.DevDatabaseId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.DevDatabaseId IS NOT NULL THEN (SELECT d.Engine, d.DatabaseName, d.FileName, d.SizeBytes, d.Sha256,
                CONVERT(char(64), HASHBYTES('SHA2_256', COALESCE(d.Prompt, N'')), 2) AS PromptSha256
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.DevDatabaseId IS NOT NULL THEN (SELECT i.Engine, i.DatabaseName, i.FileName, i.SizeBytes, i.Sha256,
                CONVERT(char(64), HASHBYTES('SHA2_256', COALESCE(i.Prompt, N'')), 2) AS PromptSha256
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.DevDatabaseId = i.DevDatabaseId
    CROSS JOIN [${schema}].fnAuditWho() w;
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

-- Source control tokens (Admin → Source control, credentials.py): a read-only token for each organization
-- the scans may read (Purpose read, Scope: the organization / group / collection), and a write token for
-- each output repository (Purpose write, Scope: the repository URL). An organization without a read token
-- is never scanned. TokenSealed is sealed for the scan worker's public key: the web UI can seal a token
-- but not open it, the admin role is not granted SELECT on it, and it is never copied to AuditLog (only
-- when it was replaced, TokenSetAt). The worker records when and how it last used a token. Purpose llm is
-- the LLM the scans ask (Provider anthropic: the Claude API, openai: an OpenAI-compatible server; ApiUrl,
-- Model, and its key in TokenSealed, sealed as an empty string when the server needs none).
IF OBJECT_ID(N'[${schema}].SourceCredential', N'U') IS NULL
CREATE TABLE [${schema}].SourceCredential (
    CredentialId  int IDENTITY(1,1) NOT NULL CONSTRAINT PK_SourceCredential PRIMARY KEY,
    Purpose       nvarchar(10)  NOT NULL CONSTRAINT CK_SourceCredential_Purpose CHECK (Purpose IN (N'read', N'write', N'llm')),
    Provider      nvarchar(20)  NOT NULL CONSTRAINT CK_SourceCredential_Provider CHECK (Provider IN (N'azure-devops', N'github', N'gitlab', N'anthropic', N'openai')),
    ApiUrl        nvarchar(400) NULL,
    Host          nvarchar(255) NOT NULL,
    Scope         nvarchar(400) NOT NULL,
    Model         nvarchar(200) NULL,
    Note          nvarchar(400) NULL,
    Enabled       bit NOT NULL CONSTRAINT DF_SourceCredential_Enabled DEFAULT 1,
    ExpiresOn     date NULL,
    TokenSealed   varchar(max) NOT NULL,
    KeyId         char(16) NOT NULL,
    TokenSetAt    datetime2(0) NOT NULL CONSTRAINT DF_SourceCredential_TokenSetAt DEFAULT SYSUTCDATETIME(),
    TokenSetBy    nvarchar(256) NOT NULL,
    CreatedAt     datetime2(0) NOT NULL CONSTRAINT DF_SourceCredential_CreatedAt DEFAULT SYSUTCDATETIME(),
    LastUsedAt    datetime2(0) NULL,
    LastResult    nvarchar(1000) NULL,
    CONSTRAINT CK_SourceCredential_ApiUrl CHECK ((ApiUrl LIKE N'https://_%' OR (Purpose = N'llm' AND ApiUrl LIKE N'http://_%'))
                                                 AND ApiUrl NOT LIKE N'%[<>"'' ]%'),
    CONSTRAINT CK_SourceCredential_Kind CHECK (
        (Purpose = N'read' AND Provider IN (N'azure-devops', N'github', N'gitlab'))
        OR (Purpose = N'write' AND Provider IN (N'azure-devops', N'github', N'gitlab') AND Scope LIKE N'https://_%' AND ApiUrl IS NULL)
        OR (Purpose = N'llm' AND Provider IN (N'anthropic', N'openai') AND Scope = N'llm' AND Model IS NOT NULL)),
    CONSTRAINT UQ_SourceCredential UNIQUE (Purpose, Provider, Host, Scope)
);
GO

CREATE OR ALTER TRIGGER [${schema}].trSourceCredentialAudit ON [${schema}].SourceCredential
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'SourceCredential', COALESCE(i.CredentialId, d.CredentialId),
           LEFT(COALESCE(i.Purpose, d.Purpose) + N': ' + COALESCE(i.Scope, d.Scope), 200),
           CASE WHEN d.CredentialId IS NULL THEN N'insert' WHEN i.CredentialId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.CredentialId IS NOT NULL THEN (SELECT d.Purpose, d.Provider, d.ApiUrl, d.Host, d.Scope, d.Model, d.Note, d.Enabled,
                d.ExpiresOn, d.TokenSetAt FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.CredentialId IS NOT NULL THEN (SELECT i.Purpose, i.Provider, i.ApiUrl, i.Host, i.Scope, i.Model, i.Note, i.Enabled,
                i.ExpiresOn, i.TokenSetAt FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.CredentialId = i.CredentialId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.CredentialId IS NULL OR i.CredentialId IS NULL
       OR EXISTS (SELECT i.Purpose, i.Provider, i.ApiUrl, i.Host, i.Scope, i.Model, i.Note, i.Enabled, i.ExpiresOn, i.TokenSetAt, i.KeyId
                  EXCEPT SELECT d.Purpose, d.Provider, d.ApiUrl, d.Host, d.Scope, d.Model, d.Note, d.Enabled, d.ExpiresOn, d.TokenSetAt, d.KeyId);
END;
GO

-- Lab services turned on or off (and the administrator's note) in the change history.
CREATE OR ALTER TRIGGER [${schema}].trLabServiceAudit ON [${schema}].LabService
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'LabService', COALESCE(i.LabServiceId, d.LabServiceId),
           COALESCE(i.Title, d.Title),
           CASE WHEN d.LabServiceId IS NULL THEN N'insert' WHEN i.LabServiceId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.LabServiceId IS NOT NULL THEN (SELECT d.Enabled, d.Note
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.LabServiceId IS NOT NULL THEN (SELECT i.Enabled, i.Note
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.LabServiceId = i.LabServiceId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.LabServiceId IS NULL OR i.LabServiceId IS NULL
       OR EXISTS (SELECT i.Enabled, i.Note EXCEPT SELECT d.Enabled, d.Note);
END;
GO

-- Least-privilege roles. Add database users to them (docs/sign-in.md#roles for the web UI roles on top of them):
--   ${schema}_writer: the scanner; inserts results, never touches the people-maintained columns
--   ${schema}_reader: the web UI and report readers; views and lookup tables only
--   ${schema}_admin: the admin pages of the web UI (and people editing with SQL): business units,
--                    products, the application mapping, organization scans and enabling/disabling their
--                    repositories, the rule review; reads the audit log; also a reader
--   The scan worker (`containerizer worker`) uses a ${schema}_writer login too.
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
GRANT SELECT ON [${schema}].OrgScan TO [${schema}_writer];
GRANT UPDATE ON [${schema}].OrgScan (NextRunAt) TO [${schema}_writer];
GRANT SELECT ON [${schema}].OrgScanRun TO [${schema}_writer];
GRANT UPDATE ON [${schema}].OrgScanRun (Status, Worker, StartedAt, HeartbeatAt, FinishedAt, ImageTag, ReposListed, ReposTotal,
    ReposDone, ReposNew, ReposDeployed, ReposSkipped, ReposErrors, CurrentRepo, Message) TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].OrgRepository TO [${schema}_writer];
GRANT UPDATE ON [${schema}].OrgRepository (ProjectName, Name, ExternalId, CloneUrl, WebUrl, RepositoryUrl, DefaultBranch, AppName,
    LastActivityAt, LastSeenAt, RemovedAt, SkipStatus, SkipReason, LastStatus, LastReason, LastCommit, LastCommitAt,
    LastRating, LastScannedAt, LastRunId, LastSeconds, LastDetail) TO [${schema}_writer];
GRANT EXECUTE ON [${schema}].QueueOrgScanRun TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].OrgProject TO [${schema}_writer];
GRANT UPDATE ON [${schema}].OrgProject (LastSeenAt, RemovedAt) TO [${schema}_writer];
GRANT SELECT ON [${schema}].vOrgRepository TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].SandboxCheck TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].SandboxIdpClient TO [${schema}_writer];
GRANT EXECUTE ON [${schema}].ProposeRuleCandidate TO [${schema}_writer];

GRANT SELECT ON [${schema}].vApplicationLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vComponentLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vFindingLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vComponentMigrationLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vUnmapped TO [${schema}_reader];
GRANT SELECT ON [${schema}].vAssessmentHistory TO [${schema}_reader];
GRANT SELECT ON [${schema}].vSandboxLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vSandboxIdpLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].Rating TO [${schema}_reader];
GRANT SELECT ON [${schema}].BusinessUnit TO [${schema}_reader];
GRANT SELECT ON [${schema}].Product TO [${schema}_reader];
GRANT SELECT ON [${schema}].ApplicationAssessment (AssessmentId, ApplicationId, AssessedAt, Rating, Score, Confidence, Verified) TO [${schema}_reader];

GRANT SELECT, INSERT, UPDATE, DELETE ON [${schema}].BusinessUnit TO [${schema}_admin];
GRANT SELECT, INSERT, UPDATE, DELETE ON [${schema}].Product TO [${schema}_admin];
GRANT SELECT ON [${schema}].Application TO [${schema}_admin];
GRANT UPDATE ON [${schema}].Application (ProductId, DisplayName, Description, Owner, Retired) TO [${schema}_admin];
GRANT SELECT ON [${schema}].AuditLog TO [${schema}_admin];
GRANT SELECT, INSERT ON [${schema}].AccessLog TO [${schema}_admin];
GRANT SELECT, INSERT, UPDATE, DELETE ON [${schema}].DevDatabase TO [${schema}_admin];
GRANT SELECT ON [${schema}].DevDatabase TO [${schema}_writer];
GRANT SELECT, INSERT, UPDATE, DELETE ON [${schema}].OrgScan TO [${schema}_admin];
GRANT SELECT ON [${schema}].OrgScanRun TO [${schema}_admin];
GRANT SELECT ON [${schema}].OrgRepository TO [${schema}_admin];
GRANT UPDATE ON [${schema}].OrgRepository (AdminState, AdminNote) TO [${schema}_admin];
GRANT SELECT ON [${schema}].OrgProject TO [${schema}_admin];
GRANT UPDATE ON [${schema}].OrgProject (AdminState, AdminNote) TO [${schema}_admin];
GRANT SELECT ON [${schema}].vOrgRepository TO [${schema}_admin];
GRANT EXECUTE ON [${schema}].QueueOrgScanRun TO [${schema}_admin];
GRANT EXECUTE ON [${schema}].CancelOrgScanRun TO [${schema}_admin];
GRANT SELECT ON [${schema}].RuleCandidate TO [${schema}_admin];
GRANT UPDATE ON [${schema}].RuleCandidate (Status, ReviewedBy, ReviewedByName, ReviewedAt, ReviewNote, FinalYaml, AppliedAs,
                                           PullRequestUrl, ClaimedBy, ClaimedAt) TO [${schema}_admin];
GRANT SELECT ON [${schema}].RuleEvidence TO [${schema}_admin];
-- source control tokens: the admin pages add, replace and remove them but cannot read the sealed token back;
-- the worker reads them and records their use
GRANT SELECT ON [${schema}].SourceCredential (CredentialId, Purpose, Provider, ApiUrl, Host, Scope, Model, Note, Enabled, ExpiresOn, KeyId,
    TokenSetAt, TokenSetBy, CreatedAt, LastUsedAt, LastResult) TO [${schema}_admin];
GRANT INSERT, DELETE ON [${schema}].SourceCredential TO [${schema}_admin];
GRANT UPDATE ON [${schema}].SourceCredential (Model, Note, Enabled, ExpiresOn, TokenSealed, KeyId, TokenSetAt, TokenSetBy) TO [${schema}_admin];
GRANT SELECT ON [${schema}].SourceCredential TO [${schema}_writer];
GRANT UPDATE ON [${schema}].SourceCredential (LastUsedAt, LastResult) TO [${schema}_writer];
-- lab services: administrators turn them on or off; the system agent applies it
GRANT SELECT ON [${schema}].LabService TO [${schema}_admin];
GRANT UPDATE ON [${schema}].LabService (Enabled, Note, ChangedAt) TO [${schema}_admin];
IF IS_ROLEMEMBER(N'${schema}_reader', N'${schema}_admin') = 0 ALTER ROLE [${schema}_reader] ADD MEMBER [${schema}_admin];
GO

-- Approving learned rules from the admin pages (rulereview.py, docs/rule-review.md). The internal rules
-- repository is set by administrators on Admin -> Rule review (one row); its token is the write token
-- registered for that repository URL under Source control, which only the scan worker can open. So the
-- web UI does not push: it asks for the approval (Approve* columns), and the worker opens the pull request
-- and records the decision through FinishRuleApproval, in the reviewer's name.
IF OBJECT_ID(N'[${schema}].RulesRepository', N'U') IS NULL
CREATE TABLE [${schema}].RulesRepository (
    RulesRepositoryId int NOT NULL CONSTRAINT PK_RulesRepository PRIMARY KEY CONSTRAINT CK_RulesRepository_One CHECK (RulesRepositoryId = 1),
    RepoUrl       nvarchar(400) NOT NULL CONSTRAINT CK_RulesRepository_Url CHECK (RepoUrl LIKE N'https://_%' AND RepoUrl NOT LIKE N'%[<>"'' ]%'),
    Provider      nvarchar(20)  NOT NULL CONSTRAINT CK_RulesRepository_Provider CHECK (Provider IN (N'azure-devops', N'github', N'gitlab')),
    ApiUrl        nvarchar(400) NULL CONSTRAINT CK_RulesRepository_ApiUrl CHECK (ApiUrl LIKE N'https://_%' AND ApiUrl NOT LIKE N'%[<>"'' ]%'),
    Branch        nvarchar(200) NOT NULL CONSTRAINT DF_RulesRepository_Branch DEFAULT N'main',
    Path          nvarchar(200) NOT NULL CONSTRAINT DF_RulesRepository_Path DEFAULT N'rules',
    ChangedAt     datetime2(0)  NOT NULL CONSTRAINT DF_RulesRepository_ChangedAt DEFAULT SYSUTCDATETIME()
);
GO
CREATE OR ALTER TRIGGER [${schema}].trRulesRepositoryAudit ON [${schema}].RulesRepository
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'RulesRepository', COALESCE(i.RulesRepositoryId, d.RulesRepositoryId),
           LEFT(COALESCE(i.RepoUrl, d.RepoUrl), 200),
           CASE WHEN d.RulesRepositoryId IS NULL THEN N'insert' WHEN i.RulesRepositoryId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.RulesRepositoryId IS NOT NULL THEN (SELECT d.RepoUrl, d.Provider, d.ApiUrl, d.Branch, d.Path
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.RulesRepositoryId IS NOT NULL THEN (SELECT i.RepoUrl, i.Provider, i.ApiUrl, i.Branch, i.Path
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.RulesRepositoryId = i.RulesRepositoryId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.RulesRepositoryId IS NULL OR i.RulesRepositoryId IS NULL
       OR EXISTS (SELECT i.RepoUrl, i.Provider, i.ApiUrl, i.Branch, i.Path EXCEPT SELECT d.RepoUrl, d.Provider, d.ApiUrl, d.Branch, d.Path);
END;
GO
IF COL_LENGTH(N'[${schema}].RuleCandidate', N'ApproveRequestedAt') IS NULL
ALTER TABLE [${schema}].RuleCandidate ADD
    ApproveRequestedAt datetime2(0)   NULL,         -- a reviewer approved it; the worker opens the pull request
    ApproveBy          nvarchar(256)  NULL,
    ApproveByName      nvarchar(256)  NULL,
    ApproveRole        nvarchar(40)   NULL,
    ApproveYaml        nvarchar(max)  NULL,         -- the rule as the reviewer approved it (with their edits)
    ApproveNote        nvarchar(1000) NULL,
    ApproveStartedAt   datetime2(0)   NULL,         -- the worker took it (taken again after 15 minutes)
    ApplyError         nvarchar(1000) NULL;         -- why the last approval did not go through
GO

-- The worker takes the oldest approval waiting for it (one worker at a time per candidate).
CREATE OR ALTER PROCEDURE [${schema}].NextRuleApproval
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;
    DECLARE @id int;
    BEGIN TRANSACTION;
    SELECT TOP (1) @id = CandidateId FROM [${schema}].RuleCandidate WITH (UPDLOCK, READPAST, ROWLOCK)
    WHERE Status = N'pending' AND ApproveRequestedAt IS NOT NULL
      AND (ApproveStartedAt IS NULL OR ApproveStartedAt < DATEADD(minute, -15, SYSUTCDATETIME()))
    ORDER BY ApproveRequestedAt;
    IF @id IS NOT NULL
        UPDATE [${schema}].RuleCandidate SET ApproveStartedAt = SYSUTCDATETIME() WHERE CandidateId = @id;
    COMMIT TRANSACTION;
    SELECT CandidateId, Kind, RuleId, Title, TargetFile, RuleYaml, Confidence, Model, LearnedFrom, SeenCount,
           ApproveBy, ApproveByName, ApproveRole, ApproveYaml, ApproveNote
    FROM [${schema}].RuleCandidate WHERE CandidateId = @id;
END;
GO

-- The worker's result: approved (the pull request is open) in the reviewer's name, or the request is
-- dropped with the reason and the candidate waits again.
CREATE OR ALTER PROCEDURE [${schema}].FinishRuleApproval
    @CandidateId int, @FinalYaml nvarchar(max), @PullRequestUrl nvarchar(400), @Error nvarchar(1000)
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @by nvarchar(256), @name nvarchar(256), @role nvarchar(40);
    SELECT @by = ApproveBy, @name = ApproveByName, @role = ApproveRole FROM [${schema}].RuleCandidate
    WHERE CandidateId = @CandidateId AND Status = N'pending' AND ApproveStartedAt IS NOT NULL;
    IF @by IS NULL
    BEGIN
        SELECT CAST(0 AS int) AS Updated;
        RETURN;
    END
    -- the change history names the reviewer, not the worker's login
    EXEC sp_set_session_context N'containerizer.user', @by;
    EXEC sp_set_session_context N'containerizer.user_name', @name;
    EXEC sp_set_session_context N'containerizer.via', N'rule review';
    EXEC sp_set_session_context N'containerizer.role', @role;
    IF @Error IS NULL
        UPDATE [${schema}].RuleCandidate SET Status = N'approved', ReviewedBy = ApproveBy, ReviewedByName = ApproveByName,
               ReviewedAt = SYSUTCDATETIME(), ReviewNote = ApproveNote, FinalYaml = @FinalYaml, AppliedAs = N'pr',
               PullRequestUrl = @PullRequestUrl, ClaimedBy = NULL, ClaimedAt = NULL, ApproveRequestedAt = NULL,
               ApproveStartedAt = NULL, ApplyError = NULL
        WHERE CandidateId = @CandidateId AND Status = N'pending' AND ApproveStartedAt IS NOT NULL;
    ELSE
        UPDATE [${schema}].RuleCandidate SET ApproveRequestedAt = NULL, ApproveStartedAt = NULL, ApplyError = @Error,
               ClaimedBy = NULL, ClaimedAt = NULL
        WHERE CandidateId = @CandidateId AND Status = N'pending' AND ApproveStartedAt IS NOT NULL;
    DECLARE @n int = @@ROWCOUNT;
    EXEC sp_set_session_context N'containerizer.user', NULL;
    EXEC sp_set_session_context N'containerizer.user_name', NULL;
    EXEC sp_set_session_context N'containerizer.via', NULL;
    EXEC sp_set_session_context N'containerizer.role', NULL;
    SELECT @n AS Updated;
END;
GO
GRANT SELECT, INSERT, UPDATE, DELETE ON [${schema}].RulesRepository TO [${schema}_admin];
GRANT SELECT ON [${schema}].RulesRepository TO [${schema}_writer];
GRANT UPDATE ON [${schema}].RuleCandidate (ApproveRequestedAt, ApproveBy, ApproveByName, ApproveRole, ApproveYaml, ApproveNote,
                                           ApproveStartedAt, ApplyError) TO [${schema}_admin];
GRANT EXECUTE ON [${schema}].NextRuleApproval TO [${schema}_writer];
GRANT EXECUTE ON [${schema}].FinishRuleApproval TO [${schema}_writer];
GO

IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 2) INSERT [${schema}].SchemaVersion (Version) VALUES (2);
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 3) INSERT [${schema}].SchemaVersion (Version) VALUES (3);
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 4) INSERT [${schema}].SchemaVersion (Version) VALUES (4);
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 5) INSERT [${schema}].SchemaVersion (Version) VALUES (5);
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 6) INSERT [${schema}].SchemaVersion (Version) VALUES (6);
GO
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 7) INSERT [${schema}].SchemaVersion (Version) VALUES (7);
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 8) INSERT [${schema}].SchemaVersion (Version) VALUES (8);
GO
-- 9: rule review (RuleCandidate, RuleEvidence)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 9) INSERT [${schema}].SchemaVersion (Version) VALUES (9);
GO
-- 10: source control tokens and the LLM (SourceCredential)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 10) INSERT [${schema}].SchemaVersion (Version) VALUES (10);
GO
-- 11: SandboxCheck.Url, UrlCheck (Sandbox HTTPS)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 11) INSERT [${schema}].SchemaVersion (Version) VALUES (11);
GO
-- 12: lab services (LabService)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 12) INSERT [${schema}].SchemaVersion (Version) VALUES (12);
GO
-- 13: sandbox identity provider registrations (SandboxIdpClient, vSandboxIdpLatest)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 13) INSERT [${schema}].SchemaVersion (Version) VALUES (13);
-- 14: dev database backups for PostgreSQL and MySQL (CK_DevDatabase_Engine); more lab services
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 14) INSERT [${schema}].SchemaVersion (Version) VALUES (14);
-- 15: approving learned rules from the admin pages (RulesRepository, RuleCandidate.Approve*)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 15) INSERT [${schema}].SchemaVersion (Version) VALUES (15);
GO
-- 16: work estimates removed (EffortDays dropped from the assessment tables and views)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 16) INSERT [${schema}].SchemaVersion (Version) VALUES (16);
GO
-- 17: discovery runs and projects of organization scans (OrgScanRun.Kind, OrgProject); disabled repositories
-- and projects left out of the results views
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 17) INSERT [${schema}].SchemaVersion (Version) VALUES (17);
GO
-- 18: LLM-heavy mode of organization scans (OrgScan.LlmHeavy)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 18) INSERT [${schema}].SchemaVersion (Version) VALUES (18);
GO

-- 19: the LLM queue (llmqueue.py, docs/source-control.md#queued-llm-reviews). LLM jobs that do not hold up
-- the scans: the queue runner (`containerizer llm-queue`) asks them when Admin -> LLM queue lets it. Kind is
-- the kind of job ('review': a component review a scan with queued LLM reviews did not ask); Payload is
-- what the kind's handler needs (for a review: the exact prompt, model and answer cache key), Result its
-- answer (JSON) and Summary one line of it. Reason, RuleVerdict and Confidence are the component review's,
-- for the queue page. The order is COALESCE(AdminRank, Priority), highest first: administrators move jobs
-- by setting AdminRank. One job per Kind and DedupeKey waits at a time (QueueLlmJob). EstInputTokens is
-- estimated from the prompt when queued (llmqueue.estimate_tokens); InputTokens, OutputTokens and Seconds
-- are what the answer really took, with the Endpoint that gave it.
IF OBJECT_ID(N'[${schema}].LlmJob', N'U') IS NULL
CREATE TABLE [${schema}].LlmJob (
    JobId          int IDENTITY(1,1) NOT NULL CONSTRAINT PK_LlmJob PRIMARY KEY,
    Kind           nvarchar(20)   NOT NULL CONSTRAINT CK_LlmJob_Kind CHECK (Kind IN (N'review', N'refactor')),
    Reason         nvarchar(40)   NULL,              -- review: uncertain, second-opinion
    Status         nvarchar(20)   NOT NULL CONSTRAINT DF_LlmJob_Status DEFAULT N'queued'
                   CONSTRAINT CK_LlmJob_Status CHECK (Status IN (N'queued', N'running', N'answered', N'failed', N'skipped')),
    Priority       int            NOT NULL,          -- computed by the side that queued it (llmqueue.priority)
    AdminRank      float          NULL,              -- set by people: replaces Priority in the order
    ScanId         int            NULL CONSTRAINT FK_LlmJob_Scan REFERENCES [${schema}].OrgScan (ScanId),
    RepositoryId   int            NULL CONSTRAINT FK_LlmJob_Repository REFERENCES [${schema}].OrgRepository (RepositoryId),
    Repository     nvarchar(400)  NULL,              -- project/repository (organization scans) or the app name
    App            nvarchar(200)  NULL,
    SourceKey      nvarchar(400)  NULL,              -- as Application.SourceKey
    ApplicationId  int            NULL CONSTRAINT FK_LlmJob_Application REFERENCES [${schema}].Application (ApplicationId),
    AssessmentId   int            NULL,              -- the assessment a job is about, when there is one
    Component      nvarchar(200)  NULL,
    ProjectPath    nvarchar(400)  NULL,              -- as Component.ProjectPath
    RuleVerdict    nvarchar(20)   NULL,
    Confidence     decimal(4,2)   NULL,              -- the rules' confidence
    DedupeKey      nvarchar(64)   NOT NULL,          -- review: the answer cache key
    Model          nvarchar(200)  NULL,
    RequestedBy    nvarchar(256)  NULL,              -- "scan <name>", "command line" or the person who ordered it
    Payload        nvarchar(max)  NOT NULL CONSTRAINT CK_LlmJob_Payload CHECK (ISJSON(Payload) = 1),
    Result         nvarchar(max)  NULL CONSTRAINT CK_LlmJob_Result CHECK (Result IS NULL OR ISJSON(Result) = 1),
    Summary        nvarchar(400)  NULL,
    Error          nvarchar(1000) NULL,
    Note           nvarchar(400)  NULL,
    InputChars     int            NULL,              -- characters of everything sent to the LLM (system, prompt, schema)
    EstInputTokens int            NULL,              -- InputChars / 3.5 when queued; the queue page uses the learned ratio
    InputTokens    int            NULL,              -- what the answer took
    OutputTokens   int            NULL,
    Endpoint       nvarchar(400)  NULL,              -- the LLM that answered: backend, server URL, model
    Parallel       tinyint        NULL,              -- jobs the runner was asking at the same time
    Attempts       int            NOT NULL CONSTRAINT DF_LlmJob_Attempts DEFAULT 0,
    NotBefore      datetime2(0)   NULL,              -- a failed attempt is tried again after this
    QueuedAt       datetime2(0)   NOT NULL CONSTRAINT DF_LlmJob_QueuedAt DEFAULT SYSUTCDATETIME(),
    StartedAt      datetime2(0)   NULL,
    HeartbeatAt    datetime2(0)   NULL,
    FinishedAt     datetime2(0)   NULL,
    Runner         nvarchar(256)  NULL,
    Seconds        decimal(9,1)   NULL
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_LlmJob_Status' AND object_id = OBJECT_ID(N'[${schema}].LlmJob'))
CREATE INDEX IX_LlmJob_Status ON [${schema}].LlmJob (Status, Kind) INCLUDE (Priority, AdminRank, NotBefore, QueuedAt);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_LlmJob_Dedupe' AND object_id = OBJECT_ID(N'[${schema}].LlmJob'))
CREATE INDEX IX_LlmJob_Dedupe ON [${schema}].LlmJob (DedupeKey, Kind) INCLUDE (Status, FinishedAt);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_LlmJob_Source' AND object_id = OBJECT_ID(N'[${schema}].LlmJob'))
CREATE INDEX IX_LlmJob_Source ON [${schema}].LlmJob (SourceKey, ProjectPath) INCLUDE (Kind, Status);
GO

-- What the queue runner learned about each LLM endpoint (backend, server URL and model), for the estimates on
-- the queue page: Kind '*' holds the endpoint's characters per input token and speed (prompt and generated
-- tokens per second when the server reports timings, else tokens per second overall, as observed with
-- Parallel jobs at once), the other rows the output tokens per job kind. Each figure is a moving average
-- that weighs the newest answer by 0.2 (llmqueue.ALPHA). Not audited: statistics only.
IF OBJECT_ID(N'[${schema}].LlmSpeed', N'U') IS NULL
CREATE TABLE [${schema}].LlmSpeed (
    Endpoint              nvarchar(400) NOT NULL,
    Kind                  nvarchar(20)  NOT NULL,
    Model                 nvarchar(200) NULL,
    CharsPerToken         float NULL,
    PromptTokensPerSecond float NULL,
    GenTokensPerSecond    float NULL,
    TokensPerSecond       float NULL,
    OutputTokens          float NULL,
    Parallel              tinyint NULL,
    Samples               int NOT NULL CONSTRAINT DF_LlmSpeed_Samples DEFAULT 0,
    UpdatedAt             datetime2(0) NOT NULL CONSTRAINT DF_LlmSpeed_UpdatedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT PK_LlmSpeed PRIMARY KEY (Endpoint, Kind)
);
GO

-- When the queue runner may start jobs (one row, Admin -> LLM queue). WindowDays: Mon=1 ... Sun=64, 0 every
-- day; WindowStart/WindowEnd: minutes after midnight UTC, both NULL for all day; a window ending before it
-- starts wraps midnight. OnlyWhenIdle: no scan running and the 1-minute load per CPU below MaxLoadPerCpu.
IF OBJECT_ID(N'[${schema}].LlmQueueSettings', N'U') IS NULL
CREATE TABLE [${schema}].LlmQueueSettings (
    SettingsId     int NOT NULL CONSTRAINT PK_LlmQueueSettings PRIMARY KEY CONSTRAINT CK_LlmQueueSettings_One CHECK (SettingsId = 1),
    Paused         bit NOT NULL CONSTRAINT DF_LlmQueueSettings_Paused DEFAULT 0,
    WindowDays     tinyint NOT NULL CONSTRAINT DF_LlmQueueSettings_Days DEFAULT 0
                   CONSTRAINT CK_LlmQueueSettings_Days CHECK (WindowDays BETWEEN 0 AND 127),
    WindowStart    smallint NULL CONSTRAINT CK_LlmQueueSettings_Start CHECK (WindowStart BETWEEN 0 AND 1439),
    WindowEnd      smallint NULL CONSTRAINT CK_LlmQueueSettings_End CHECK (WindowEnd BETWEEN 0 AND 1439),
    OnlyWhenIdle   bit NOT NULL CONSTRAINT DF_LlmQueueSettings_Idle DEFAULT 1,
    MaxLoadPerCpu  decimal(4,2) NOT NULL CONSTRAINT DF_LlmQueueSettings_Load DEFAULT 0.5
                   CONSTRAINT CK_LlmQueueSettings_Load CHECK (MaxLoadPerCpu BETWEEN 0 AND 16),
    Parallel       tinyint NOT NULL CONSTRAINT DF_LlmQueueSettings_Parallel DEFAULT 1
                   CONSTRAINT CK_LlmQueueSettings_Parallel CHECK (Parallel BETWEEN 1 AND 16),
    ChangedAt      datetime2(0) NOT NULL CONSTRAINT DF_LlmQueueSettings_ChangedAt DEFAULT SYSUTCDATETIME(),
    CONSTRAINT CK_LlmQueueSettings_Window CHECK ((WindowStart IS NULL AND WindowEnd IS NULL)
                                                 OR (WindowStart IS NOT NULL AND WindowEnd IS NOT NULL))
);
GO
-- the one settings row, seeded before its audit trigger exists: a default is not a change anyone made
IF NOT EXISTS (SELECT 1 FROM [${schema}].LlmQueueSettings) INSERT [${schema}].LlmQueueSettings (SettingsId) VALUES (1);
GO

-- Queue a job, unless one of the same Kind and DedupeKey is already queued or running. Returns the JobId
-- (0: one is waiting). A newer job about the same component replaces a queued older one (its code or the
-- rules changed since): that one is skipped as superseded.
CREATE OR ALTER PROCEDURE [${schema}].QueueLlmJob @Kind nvarchar(20), @Reason nvarchar(40) = NULL, @ScanId int = NULL,
    @ProjectName nvarchar(200) = NULL, @RepoName nvarchar(200) = NULL, @Repository nvarchar(400) = NULL,
    @App nvarchar(200) = NULL, @SourceKey nvarchar(400) = NULL, @ApplicationId int = NULL, @AssessmentId int = NULL,
    @Component nvarchar(200) = NULL, @ProjectPath nvarchar(400) = NULL, @RuleVerdict nvarchar(20) = NULL,
    @Confidence decimal(4,2) = NULL, @Priority int, @DedupeKey nvarchar(64), @Model nvarchar(200) = NULL,
    @RequestedBy nvarchar(256) = NULL, @InputChars int = NULL, @EstInputTokens int = NULL, @Payload nvarchar(max)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    DECLARE @id int = 0;
    BEGIN TRANSACTION;
    IF NOT EXISTS (SELECT 1 FROM [${schema}].LlmJob WITH (UPDLOCK, HOLDLOCK)
                   WHERE Kind = @Kind AND DedupeKey = @DedupeKey AND Status IN (N'queued', N'running'))
    BEGIN
        IF @SourceKey IS NOT NULL AND @ProjectPath IS NOT NULL
            UPDATE [${schema}].LlmJob SET Status = N'skipped', Note = N'superseded by a newer scan', FinishedAt = SYSUTCDATETIME()
            WHERE Status = N'queued' AND Kind = @Kind AND SourceKey = @SourceKey AND ProjectPath = @ProjectPath;
        INSERT [${schema}].LlmJob (Kind, Reason, Priority, ScanId, RepositoryId, Repository, App, SourceKey, ApplicationId,
                                   AssessmentId, Component, ProjectPath, RuleVerdict, Confidence, DedupeKey, Model,
                                   RequestedBy, InputChars, EstInputTokens, Payload)
        SELECT @Kind, @Reason, @Priority, @ScanId,
               (SELECT r.RepositoryId FROM [${schema}].OrgRepository r
                WHERE r.ScanId = @ScanId AND r.ProjectName = @ProjectName AND r.Name = @RepoName),
               @Repository, @App, @SourceKey,
               COALESCE(@ApplicationId, (SELECT a.ApplicationId FROM [${schema}].Application a WHERE a.SourceKey = @SourceKey)),
               @AssessmentId, @Component, @ProjectPath, @RuleVerdict, @Confidence, @DedupeKey, @Model,
               COALESCE(@RequestedBy, w.ChangedBy), @InputChars, @EstInputTokens, @Payload
        FROM [${schema}].fnAuditWho() w;
        SET @id = SCOPE_IDENTITY();
    END
    COMMIT;
    SELECT @id AS JobId;
END;
GO

-- Jobs queued, moved, skipped, queued again, answered or failed (not the runner taking one, nor its heartbeats).
CREATE OR ALTER TRIGGER [${schema}].trLlmJobAudit ON [${schema}].LlmJob
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'LlmJob', COALESCE(i.JobId, d.JobId),
           LEFT(COALESCE(i.Repository, d.Repository, i.App, d.App, i.Kind, d.Kind)
                + COALESCE(N' / ' + COALESCE(i.Component, d.Component), N''), 200),
           CASE WHEN d.JobId IS NULL THEN N'insert' WHEN i.JobId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.JobId IS NOT NULL THEN (SELECT d.Kind, d.Reason, d.Status, d.Priority, d.AdminRank, d.Summary, d.Error,
                d.RequestedBy FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.JobId IS NOT NULL THEN (SELECT i.Kind, i.Reason, i.Status, i.Priority, i.AdminRank, i.Summary, i.Error,
                i.RequestedBy FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.JobId = i.JobId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.JobId IS NULL OR i.JobId IS NULL
       OR (i.Status <> N'running' AND EXISTS (SELECT i.Status, i.AdminRank EXCEPT SELECT d.Status, d.AdminRank));
END;
GO

CREATE OR ALTER TRIGGER [${schema}].trLlmQueueSettingsAudit ON [${schema}].LlmQueueSettings
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'LlmQueueSettings', COALESCE(i.SettingsId, d.SettingsId), N'LLM queue',
           CASE WHEN d.SettingsId IS NULL THEN N'insert' WHEN i.SettingsId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.SettingsId IS NOT NULL THEN (SELECT d.Paused, d.WindowDays, d.WindowStart, d.WindowEnd, d.OnlyWhenIdle,
                d.MaxLoadPerCpu, d.Parallel FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.SettingsId IS NOT NULL THEN (SELECT i.Paused, i.WindowDays, i.WindowStart, i.WindowEnd, i.OnlyWhenIdle,
                i.MaxLoadPerCpu, i.Parallel FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.SettingsId = i.SettingsId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.SettingsId IS NULL OR i.SettingsId IS NULL
       OR EXISTS (SELECT i.Paused, i.WindowDays, i.WindowStart, i.WindowEnd, i.OnlyWhenIdle, i.MaxLoadPerCpu, i.Parallel
                  EXCEPT SELECT d.Paused, d.WindowDays, d.WindowStart, d.WindowEnd, d.OnlyWhenIdle, d.MaxLoadPerCpu, d.Parallel);
END;
GO

-- The latest component review of every component (not the superseded or skipped ones), for the results pages.
CREATE OR ALTER VIEW [${schema}].vLlmReviewLatest AS
SELECT x.ApplicationId, c.ComponentId, x.JobId, x.Reason, x.Status, x.QueuedAt, x.FinishedAt, x.Model,
       r.verdict AS Verdict, TRY_CAST(r.confidence AS decimal(4,2)) AS LlmConfidence, r.reasoning AS Reasoning
FROM (SELECT j.JobId, j.Reason, j.Status, j.QueuedAt, j.FinishedAt, j.Model, j.Result, j.ProjectPath, a.ApplicationId,
             ROW_NUMBER() OVER (PARTITION BY j.SourceKey, j.ProjectPath ORDER BY j.JobId DESC) AS N
      FROM [${schema}].LlmJob j
      JOIN [${schema}].Application a ON a.SourceKey = j.SourceKey
      WHERE j.Kind = N'review' AND j.Status <> N'skipped') x
JOIN [${schema}].Component c ON c.ApplicationId = x.ApplicationId AND c.ProjectPath = x.ProjectPath
OUTER APPLY OPENJSON(x.Result) WITH (verdict nvarchar(20), confidence float, reasoning nvarchar(max)) r
WHERE x.N = 1;
GO

GRANT SELECT ON [${schema}].LlmJob TO [${schema}_writer];
GRANT UPDATE ON [${schema}].LlmJob (Status, Runner, StartedAt, HeartbeatAt, FinishedAt, Attempts, NotBefore, Result, Summary,
    Error, Note, Seconds, InputTokens, OutputTokens, Endpoint, Parallel) TO [${schema}_writer];
GRANT SELECT, INSERT, UPDATE ON [${schema}].LlmSpeed TO [${schema}_writer];
GRANT SELECT ON [${schema}].LlmSpeed TO [${schema}_admin];
GRANT EXECUTE ON [${schema}].QueueLlmJob TO [${schema}_writer];
GRANT SELECT ON [${schema}].LlmQueueSettings TO [${schema}_writer];
GRANT SELECT ON [${schema}].LlmJob TO [${schema}_admin];
GRANT UPDATE ON [${schema}].LlmJob (AdminRank, Status, Attempts, NotBefore, Error, Note, FinishedAt) TO [${schema}_admin];
GRANT EXECUTE ON [${schema}].QueueLlmJob TO [${schema}_admin];
GRANT SELECT, UPDATE ON [${schema}].LlmQueueSettings TO [${schema}_admin];
GRANT SELECT ON [${schema}].vLlmReviewLatest TO [${schema}_reader];
GO
-- 19: the LLM queue (LlmJob, LlmSpeed, LlmQueueSettings, vLlmReviewLatest) and queued LLM reviews of organization scans
-- (OrgScan.LlmMode)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 19) INSERT [${schema}].SchemaVersion (Version) VALUES (19);
GO

-- 20: refactoring patches (refactor.py, docs/refactoring.md). An operator or administrator orders the code
-- changes of a B-rated application (or one component); the order is an LlmJob of Kind 'refactor' whose
-- Payload lists the findings to fix, the assessed commit and where the source is (the scan worker's clone),
-- and whose Result holds the patch (a `git format-patch`), its status (verified, applies-only, failed), what
-- became of each finding and the log tail of the build and run. While it runs, Summary says how far it is
-- (generating, verifying). The kind is added to CK_LlmJob_Kind of databases from schema 19.
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = N'CK_LlmJob_Kind'
           AND parent_object_id = OBJECT_ID(N'[${schema}].LlmJob') AND definition NOT LIKE N'%refactor%')
    ALTER TABLE [${schema}].LlmJob DROP CONSTRAINT CK_LlmJob_Kind;
GO
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = N'CK_LlmJob_Kind'
               AND parent_object_id = OBJECT_ID(N'[${schema}].LlmJob'))
    ALTER TABLE [${schema}].LlmJob ADD CONSTRAINT CK_LlmJob_Kind CHECK (Kind IN (N'review', N'refactor'));
GO

-- The refactoring orders of every application with their status, for the results pages (no patch, no
-- payload, nobody's name: the patches are on the admin pages, for operators and administrators).
-- Status: queued, generating, verifying, verified, applies-only, failed, cancelled (refactor.order_status).
CREATE OR ALTER VIEW [${schema}].vRefactorOrder AS
SELECT j.JobId, COALESCE(j.ApplicationId, a.ApplicationId) AS ApplicationId, j.AssessmentId, j.Component, j.ProjectPath,
       CASE WHEN j.Status = N'queued' THEN N'queued'
            WHEN j.Status = N'running' THEN CASE WHEN j.Summary LIKE N'verifying%' THEN N'verifying' ELSE N'generating' END
            WHEN j.Status = N'answered' AND JSON_VALUE(j.Result, '$$.status') IN (N'verified', N'applies-only', N'failed')
                 THEN JSON_VALUE(j.Result, '$$.status')
            WHEN j.Status = N'skipped' THEN N'cancelled'
            ELSE N'failed' END AS Status,
       j.Summary, JSON_VALUE(j.Payload, '$$.commit') AS SourceCommit, j.QueuedAt, j.StartedAt, j.FinishedAt
FROM [${schema}].LlmJob j
LEFT JOIN [${schema}].Application a ON a.SourceKey = j.SourceKey
WHERE j.Kind = N'refactor';
GO
GRANT SELECT ON [${schema}].vRefactorOrder TO [${schema}_reader];
-- what an order is made from: the latest assessment's report (the findings with their evidence) and its commit
GRANT SELECT ON [${schema}].ApplicationAssessment (ReportJson, SourceCommit, SourceBranch) TO [${schema}_admin];
GO
-- 20: refactoring patches (LlmJob Kind 'refactor', vRefactorOrder)
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 20) INSERT [${schema}].SchemaVersion (Version) VALUES (20);
GO

-- API keys for the JSON API (admin_apikeys.py): the key itself is shown once and never stored, only its
-- SHA-256. Revoked or expired keys are refused. The change history records creating and revoking a key,
-- not every use (LastUsedAt).
IF OBJECT_ID(N'[${schema}].ApiKey', N'U') IS NULL
CREATE TABLE [${schema}].ApiKey (
    ApiKeyId    int IDENTITY(1,1) NOT NULL CONSTRAINT PK_ApiKey PRIMARY KEY,
    Name        nvarchar(100)  NOT NULL,
    Prefix      char(8)        NOT NULL CONSTRAINT UQ_ApiKey_Prefix UNIQUE,
    KeyHash     binary(32)     NOT NULL,
    Role        nvarchar(10)   NOT NULL CONSTRAINT CK_ApiKey_Role CHECK (Role IN (N'read', N'full')),
    CreatedBy   nvarchar(256)  NOT NULL,
    CreatedAt   datetime2(0)   NOT NULL CONSTRAINT DF_ApiKey_CreatedAt DEFAULT SYSUTCDATETIME(),
    ExpiresAt   datetime2(0)   NULL,
    LastUsedAt  datetime2(0)   NULL,
    RevokedAt   datetime2(0)   NULL,
    RevokedBy   nvarchar(256)  NULL
);
GO
CREATE OR ALTER TRIGGER [${schema}].trApiKeyAudit ON [${schema}].ApiKey
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'ApiKey', COALESCE(i.ApiKeyId, d.ApiKeyId), COALESCE(i.Name, d.Name),
           CASE WHEN d.ApiKeyId IS NULL THEN N'insert' WHEN i.ApiKeyId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.ApiKeyId IS NOT NULL THEN (SELECT d.Name, d.Prefix, d.Role, d.ExpiresAt, d.RevokedAt, d.RevokedBy
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.ApiKeyId IS NOT NULL THEN (SELECT i.Name, i.Prefix, i.Role, i.ExpiresAt, i.RevokedAt, i.RevokedBy
                FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.ApiKeyId = i.ApiKeyId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.ApiKeyId IS NULL OR i.ApiKeyId IS NULL
       OR EXISTS (SELECT i.Name, i.Role, i.ExpiresAt, i.RevokedAt EXCEPT SELECT d.Name, d.Role, d.ExpiresAt, d.RevokedAt);
END;
GO
GRANT SELECT, INSERT ON [${schema}].ApiKey TO [${schema}_admin];
GRANT UPDATE ON [${schema}].ApiKey (LastUsedAt, RevokedAt, RevokedBy) TO [${schema}_admin];
GO
-- 21: API keys
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 21) INSERT [${schema}].SchemaVersion (Version) VALUES (21);
GO

-- 22: approval of LLM jobs. An administrator decides which jobs wait for approval before the runner takes
-- them (ApproveKinds: 'refactor', 'review' or both; ApproveMinTokens: only jobs estimated to read at least
-- this many tokens, 0: all of those kinds). Such a job is queued with Status 'approval'; approving it makes
-- it 'queued' (ApprovedBy, ApprovedAt), rejecting it 'skipped'.
IF COL_LENGTH(N'[${schema}].LlmQueueSettings', N'ApproveKinds') IS NULL
    ALTER TABLE [${schema}].LlmQueueSettings ADD ApproveKinds nvarchar(40) NULL,
        ApproveMinTokens int NOT NULL CONSTRAINT DF_LlmQueueSettings_ApproveMin DEFAULT 0
        CONSTRAINT CK_LlmQueueSettings_ApproveMin CHECK (ApproveMinTokens BETWEEN 0 AND 10000000);
GO
IF COL_LENGTH(N'[${schema}].LlmJob', N'ApprovedBy') IS NULL
    ALTER TABLE [${schema}].LlmJob ADD ApprovedBy nvarchar(256) NULL, ApprovedAt datetime2(0) NULL;
GO
IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = N'CK_LlmJob_Status'
           AND parent_object_id = OBJECT_ID(N'[${schema}].LlmJob') AND definition NOT LIKE N'%approval%')
    ALTER TABLE [${schema}].LlmJob DROP CONSTRAINT CK_LlmJob_Status;
GO
IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = N'CK_LlmJob_Status'
               AND parent_object_id = OBJECT_ID(N'[${schema}].LlmJob'))
    ALTER TABLE [${schema}].LlmJob ADD CONSTRAINT CK_LlmJob_Status
        CHECK (Status IN (N'approval', N'queued', N'running', N'answered', N'failed', N'skipped'));
GO
CREATE OR ALTER PROCEDURE [${schema}].QueueLlmJob @Kind nvarchar(20), @Reason nvarchar(40) = NULL, @ScanId int = NULL,
    @ProjectName nvarchar(200) = NULL, @RepoName nvarchar(200) = NULL, @Repository nvarchar(400) = NULL,
    @App nvarchar(200) = NULL, @SourceKey nvarchar(400) = NULL, @ApplicationId int = NULL, @AssessmentId int = NULL,
    @Component nvarchar(200) = NULL, @ProjectPath nvarchar(400) = NULL, @RuleVerdict nvarchar(20) = NULL,
    @Confidence decimal(4,2) = NULL, @Priority int, @DedupeKey nvarchar(64), @Model nvarchar(200) = NULL,
    @RequestedBy nvarchar(256) = NULL, @InputChars int = NULL, @EstInputTokens int = NULL, @Payload nvarchar(max)
AS
BEGIN
    SET NOCOUNT ON; SET XACT_ABORT ON;
    DECLARE @id int = 0, @status nvarchar(20) = N'queued';
    -- the approval policy (LlmQueueSettings): this kind, and at least that many estimated input tokens
    IF EXISTS (SELECT 1 FROM [${schema}].LlmQueueSettings s
               WHERE s.ApproveKinds IS NOT NULL
                 AND CHARINDEX(N',' + @Kind + N',', N',' + REPLACE(s.ApproveKinds, N' ', N'') + N',') > 0
                 AND COALESCE(@EstInputTokens, 0) >= s.ApproveMinTokens)
        SET @status = N'approval';
    BEGIN TRANSACTION;
    IF NOT EXISTS (SELECT 1 FROM [${schema}].LlmJob WITH (UPDLOCK, HOLDLOCK)
                   WHERE Kind = @Kind AND DedupeKey = @DedupeKey AND Status IN (N'approval', N'queued', N'running'))
    BEGIN
        IF @SourceKey IS NOT NULL AND @ProjectPath IS NOT NULL
            UPDATE [${schema}].LlmJob SET Status = N'skipped', Note = N'superseded by a newer scan', FinishedAt = SYSUTCDATETIME()
            WHERE Status IN (N'approval', N'queued') AND Kind = @Kind AND SourceKey = @SourceKey AND ProjectPath = @ProjectPath;
        INSERT [${schema}].LlmJob (Kind, Reason, Priority, ScanId, RepositoryId, Repository, App, SourceKey, ApplicationId,
                                   AssessmentId, Component, ProjectPath, RuleVerdict, Confidence, DedupeKey, Model,
                                   RequestedBy, InputChars, EstInputTokens, Payload, Status)
        SELECT @Kind, @Reason, @Priority, @ScanId,
               (SELECT r.RepositoryId FROM [${schema}].OrgRepository r
                WHERE r.ScanId = @ScanId AND r.ProjectName = @ProjectName AND r.Name = @RepoName),
               @Repository, @App, @SourceKey,
               COALESCE(@ApplicationId, (SELECT a.ApplicationId FROM [${schema}].Application a WHERE a.SourceKey = @SourceKey)),
               @AssessmentId, @Component, @ProjectPath, @RuleVerdict, @Confidence, @DedupeKey, @Model,
               COALESCE(@RequestedBy, w.ChangedBy), @InputChars, @EstInputTokens, @Payload, @status
        FROM [${schema}].fnAuditWho() w;
        SET @id = SCOPE_IDENTITY();
    END
    COMMIT;
    SELECT @id AS JobId;
END;
GO
CREATE OR ALTER TRIGGER [${schema}].trLlmQueueSettingsAudit ON [${schema}].LlmQueueSettings
AFTER INSERT, UPDATE, DELETE AS
BEGIN
    SET NOCOUNT ON;
    INSERT [${schema}].AuditLog (ChangedBy, ChangedByName, Via, TableName, RowId, RowName, Action, OldValues, NewValues)
    SELECT w.ChangedBy, w.ChangedByName, w.Via, N'LlmQueueSettings', COALESCE(i.SettingsId, d.SettingsId), N'LLM queue',
           CASE WHEN d.SettingsId IS NULL THEN N'insert' WHEN i.SettingsId IS NULL THEN N'delete' ELSE N'update' END,
           CASE WHEN d.SettingsId IS NOT NULL THEN (SELECT d.Paused, d.WindowDays, d.WindowStart, d.WindowEnd, d.OnlyWhenIdle,
                d.MaxLoadPerCpu, d.Parallel, d.ApproveKinds, d.ApproveMinTokens FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END,
           CASE WHEN i.SettingsId IS NOT NULL THEN (SELECT i.Paused, i.WindowDays, i.WindowStart, i.WindowEnd, i.OnlyWhenIdle,
                i.MaxLoadPerCpu, i.Parallel, i.ApproveKinds, i.ApproveMinTokens FOR JSON PATH, WITHOUT_ARRAY_WRAPPER, INCLUDE_NULL_VALUES) END
    FROM inserted i FULL OUTER JOIN deleted d ON d.SettingsId = i.SettingsId
    CROSS JOIN [${schema}].fnAuditWho() w
    WHERE d.SettingsId IS NULL OR i.SettingsId IS NULL
       OR EXISTS (SELECT i.Paused, i.WindowDays, i.WindowStart, i.WindowEnd, i.OnlyWhenIdle, i.MaxLoadPerCpu, i.Parallel,
                         i.ApproveKinds, i.ApproveMinTokens
                  EXCEPT SELECT d.Paused, d.WindowDays, d.WindowStart, d.WindowEnd, d.OnlyWhenIdle, d.MaxLoadPerCpu, d.Parallel,
                         d.ApproveKinds, d.ApproveMinTokens);
END;
GO
GRANT UPDATE ON [${schema}].LlmJob (ApprovedBy, ApprovedAt) TO [${schema}_admin];
GO
-- orders waiting for approval show as such on the results pages
CREATE OR ALTER VIEW [${schema}].vRefactorOrder AS
SELECT j.JobId, COALESCE(j.ApplicationId, a.ApplicationId) AS ApplicationId, j.AssessmentId, j.Component, j.ProjectPath,
       CASE WHEN j.Status = N'approval' THEN N'approval'
            WHEN j.Status = N'queued' THEN N'queued'
            WHEN j.Status = N'running' THEN CASE WHEN j.Summary LIKE N'verifying%' THEN N'verifying' ELSE N'generating' END
            WHEN j.Status = N'answered' AND JSON_VALUE(j.Result, '$$.status') IN (N'verified', N'applies-only', N'failed')
                 THEN JSON_VALUE(j.Result, '$$.status')
            WHEN j.Status = N'skipped' THEN N'cancelled'
            ELSE N'failed' END AS Status,
       j.Summary, JSON_VALUE(j.Payload, '$$.commit') AS SourceCommit, j.QueuedAt, j.StartedAt, j.FinishedAt
FROM [${schema}].LlmJob j
LEFT JOIN [${schema}].Application a ON a.SourceKey = j.SourceKey
WHERE j.Kind = N'refactor';
GO
IF NOT EXISTS (SELECT 1 FROM [${schema}].SchemaVersion WHERE Version = 22) INSERT [${schema}].SchemaVersion (Version) VALUES (22);
GO
