-- Software bills of materials (CycloneDX) per component and scan, with licence status and CVEs per
-- package. Applied by `containerizer db init` after schema.sql (same ${schema}, same roles).
--
--   ApplicationAssessment 1-* ComponentSbom 1-* SbomPackage
--
-- Kind "image": Syft on the image the security gate built (`containerizer org`), with the CVEs of the
-- gate's image scan per package and the registry digest the SBOM was attached to.
-- Kind "source": the packages the component's project files declare (assess/analyze with --sql), for
-- components that were not built. The views prefer the image SBOM of the latest assessment.
-- The full CycloneDX document is kept in ComponentSbom.Document. See docs/sbom.md.

IF OBJECT_ID(N'[${schema}].ComponentSbom', N'U') IS NULL
CREATE TABLE [${schema}].ComponentSbom (
    SbomId          int IDENTITY(1,1) NOT NULL CONSTRAINT PK_ComponentSbom PRIMARY KEY,
    AssessmentId    int            NOT NULL CONSTRAINT FK_ComponentSbom_Assessment REFERENCES [${schema}].ApplicationAssessment (AssessmentId) ON DELETE CASCADE,
    ComponentId     int            NOT NULL CONSTRAINT FK_ComponentSbom_Component REFERENCES [${schema}].Component (ComponentId),
    CreatedAt       datetime2(0)   NOT NULL CONSTRAINT DF_ComponentSbom_CreatedAt DEFAULT SYSUTCDATETIME(),
    Kind            nvarchar(10)   NOT NULL CONSTRAINT CK_ComponentSbom_Kind CHECK (Kind IN (N'image', N'source')),
    ImageRef        nvarchar(400)  NULL,             -- pushed image (kind image)
    ImageDigest     nvarchar(100)  NULL,             -- sha256:... the SBOM describes and was attached to
    Format          nvarchar(40)   NOT NULL,         -- CycloneDX 1.6
    Tool            nvarchar(100)  NULL,             -- syft 1.33.0, containerizer
    OperatingSystem nvarchar(100)  NULL,             -- of the image: ubuntu 24.04
    PackageCount    int            NOT NULL,
    Attestation     nvarchar(300)  NULL,             -- attested (cosign), attached (OCI referrer), or why not
    Document        nvarchar(max)  NOT NULL,         -- the CycloneDX JSON document
    CONSTRAINT UQ_ComponentSbom UNIQUE (AssessmentId, ComponentId, Kind)
);
GO

-- One row per package of an SBOM. LicenseStatus: allowed, unknown, warn, denied (rules/60-security.yaml
-- sbom.licenses). PolicyApplies is 0 for base-image OS packages (unless os_packages: evaluate), the
-- application's own assembly and accepted exceptions: those are shown but not counted.
IF OBJECT_ID(N'[${schema}].SbomPackage', N'U') IS NULL
CREATE TABLE [${schema}].SbomPackage (
    SbomId          int            NOT NULL CONSTRAINT FK_SbomPackage_Sbom REFERENCES [${schema}].ComponentSbom (SbomId) ON DELETE CASCADE,
    PackageNo       int            NOT NULL,
    Name            nvarchar(400)  NOT NULL,
    Version         nvarchar(200)  NULL,
    Type            nvarchar(40)   NULL,             -- purl type: nuget, npm, deb, apk, ...
    Purl            nvarchar(1000) NULL,
    License         nvarchar(1000) NULL,             -- SPDX expression, or the name as found
    LicenseSource   nvarchar(20)   NULL,             -- sbom, nuget (looked up in the nuspec)
    LicenseStatus   nvarchar(10)   NOT NULL CONSTRAINT CK_SbomPackage_LicenseStatus CHECK (LicenseStatus IN (N'allowed', N'unknown', N'warn', N'denied')),
    Scope           nvarchar(10)   NOT NULL,         -- app, os (base image package), self (the application)
    PolicyApplies   bit            NOT NULL,
    Accepted        nvarchar(400)  NULL,             -- reason of an accepted exception
    FoundBy         nvarchar(10)   NOT NULL,         -- sbom, scanner (vulnerable package the SBOM did not list)
    Critical        int            NOT NULL CONSTRAINT DF_SbomPackage_Critical DEFAULT 0,
    High            int            NOT NULL CONSTRAINT DF_SbomPackage_High DEFAULT 0,
    Medium          int            NOT NULL CONSTRAINT DF_SbomPackage_Medium DEFAULT 0,
    Low             int            NOT NULL CONSTRAINT DF_SbomPackage_Low DEFAULT 0,
    Vulns           nvarchar(max)  NULL,             -- JSON: [{id, severity, fixed, title}]
    CONSTRAINT PK_SbomPackage PRIMARY KEY (SbomId, PackageNo)
);
GO
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = N'IX_SbomPackage_Name' AND object_id = OBJECT_ID(N'[${schema}].SbomPackage'))
CREATE INDEX IX_SbomPackage_Name ON [${schema}].SbomPackage (Name, Version) INCLUDE (LicenseStatus, Critical, High);
GO

-- The SBOM of every component in the latest assessment of each application: the image SBOM when the
-- component was built, else its source SBOM.
CREATE OR ALTER VIEW [${schema}].vSbomLatest AS
SELECT l.ApplicationId, l.ApplicationName, l.ProductId, l.ProductName, l.BusinessUnitId, l.BusinessUnitName,
       s.SbomId, s.AssessmentId, s.ComponentId, c.Name AS ComponentName, c.ProjectPath, s.CreatedAt, s.Kind,
       s.ImageRef, s.ImageDigest, s.Format, s.Tool, s.OperatingSystem, s.PackageCount, s.Attestation
FROM [${schema}].vApplicationLatest l
JOIN (SELECT x.SbomId, x.AssessmentId, x.ComponentId, x.CreatedAt, x.Kind, x.ImageRef, x.ImageDigest, x.Format,
             x.Tool, x.OperatingSystem, x.PackageCount, x.Attestation,
             ROW_NUMBER() OVER (PARTITION BY x.AssessmentId, x.ComponentId
                                ORDER BY CASE x.Kind WHEN N'image' THEN 0 ELSE 1 END, x.SbomId DESC) AS Rn
      FROM [${schema}].ComponentSbom x) s ON s.AssessmentId = l.AssessmentId AND s.Rn = 1
JOIN [${schema}].Component c ON c.ComponentId = s.ComponentId;
GO

CREATE OR ALTER VIEW [${schema}].vSbomPackageLatest AS
SELECT s.ApplicationId, s.ApplicationName, s.ProductId, s.ProductName, s.BusinessUnitId, s.BusinessUnitName,
       s.SbomId, s.ComponentId, s.ComponentName, s.Kind,
       p.PackageNo, p.Name, p.Version, p.Type, p.Purl, p.License, p.LicenseSource, p.LicenseStatus, p.Scope,
       p.PolicyApplies, p.Accepted, p.FoundBy, p.Critical, p.High, p.Medium, p.Low, p.Vulns
FROM [${schema}].vSbomLatest s
JOIN [${schema}].SbomPackage p ON p.SbomId = s.SbomId;
GO

-- The CycloneDX documents of vSbomLatest (download from the web UI and the API).
CREATE OR ALTER VIEW [${schema}].vSbomDocumentLatest AS
SELECT s.ApplicationId, s.ComponentId, s.SbomId, s.Kind, s.ImageRef, s.ImageDigest, d.Document
FROM [${schema}].vSbomLatest s
JOIN [${schema}].ComponentSbom d ON d.SbomId = s.SbomId;
GO

GRANT SELECT, INSERT ON [${schema}].ComponentSbom TO [${schema}_writer];
GRANT SELECT, INSERT ON [${schema}].SbomPackage TO [${schema}_writer];
GRANT SELECT ON [${schema}].vSbomLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vSbomPackageLatest TO [${schema}_reader];
GRANT SELECT ON [${schema}].vSbomDocumentLatest TO [${schema}_reader];
GO
