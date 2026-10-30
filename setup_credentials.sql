-- ==============================================================================
-- SecureNetworkDB: Enterprise Credential Vault & SIEM Attack Monitoring System
-- Project: Enterprise Identity, Credential Vault & Threat Detection System
-- Target: Server=.\SHOAIB;Database=SecureNetworkDB;Trusted_Connection=yes;
-- ==============================================================================

USE SecureNetworkDB;
GO

-- 1. Ensure 'Password' column exists in Users table
IF NOT EXISTS (
    SELECT 1 
    FROM sys.columns 
    WHERE object_id = OBJECT_ID('Users') 
      AND name = 'Password'
)
BEGIN
    ALTER TABLE Users ADD Password VARCHAR(255) NULL;
    PRINT '[SUCCESS] Column [Password] successfully added to table [Users].';
END
ELSE
BEGIN
    PRINT '[INFO] Column [Password] already exists in table [Users].';
END
GO

-- 2. Ensure Audit_Logs table exists
IF OBJECT_ID('Audit_Logs', 'U') IS NULL
BEGIN
    CREATE TABLE Audit_Logs (
        LogID INT IDENTITY(1,1) PRIMARY KEY,
        UserID INT FOREIGN KEY REFERENCES Users(UserID),
        LoginTime DATETIME DEFAULT GETDATE(),
        Status VARCHAR(50)
    );
    PRINT '[SUCCESS] Table [Audit_Logs] created.';
END
ELSE
BEGIN
    PRINT '[INFO] Table [Audit_Logs] already exists.';
END
GO

-- 3. Ensure User_Vault Table exists for Saving & Protecting User Credentials
IF OBJECT_ID('User_Vault', 'U') IS NULL
BEGIN
    CREATE TABLE User_Vault (
        VaultID INT IDENTITY(1,1) PRIMARY KEY,
        UserID INT FOREIGN KEY REFERENCES Users(UserID),
        CredentialName VARCHAR(100),
        ProtectedSecret VARCHAR(255),
        SecurityClassification VARCHAR(30),
        LastUpdated DATETIME DEFAULT GETDATE()
    );
    PRINT '[SUCCESS] Table [User_Vault] created successfully.';
END
ELSE
BEGIN
    PRINT '[INFO] Table [User_Vault] already exists.';
END
GO

-- 4. Initial Role Credentials
-- ------------------------------------------------------------------------------
-- Credential 1: Tier 3 System Administrator (UserID: 2412348, Password: Balti123)
-- ------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM Users WHERE UserID = 2412348)
BEGIN
    UPDATE Users
    SET Username = 'balti_admin',
        ClearanceTier = 3,
        AccountStatus = 'Active',
        Password = 'Balti123'
    WHERE UserID = 2412348;
    PRINT '[SUCCESS] Tier 3 Administrator (UserID: 2412348) verified.';
END
ELSE
BEGIN
    INSERT INTO Users (UserID, Username, ClearanceTier, AccountStatus, Password)
    VALUES (2412348, 'balti_admin', 3, 'Active', 'Balti123');
    PRINT '[SUCCESS] Tier 3 Administrator (UserID: 2412348) created.';
END
GO

-- ------------------------------------------------------------------------------
-- Credential 2: Tier 2 Security Operator (UserID: 2412349, Password: Operator123)
-- ------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM Users WHERE UserID = 2412349)
BEGIN
    UPDATE Users
    SET Username = 'sarah_operator',
        ClearanceTier = 2,
        AccountStatus = 'Active',
        Password = 'Operator123'
    WHERE UserID = 2412349;
    PRINT '[SUCCESS] Tier 2 Operator (UserID: 2412349) verified.';
END
ELSE
BEGIN
    INSERT INTO Users (UserID, Username, ClearanceTier, AccountStatus, Password)
    VALUES (2412349, 'sarah_operator', 2, 'Active', 'Operator123');
    PRINT '[SUCCESS] Tier 2 Operator (UserID: 2412349) created.';
END
GO

-- ------------------------------------------------------------------------------
-- Credential 3: Tier 1 Network Analyst (UserID: 2412350, Password: Analyst123)
-- ------------------------------------------------------------------------------
IF EXISTS (SELECT 1 FROM Users WHERE UserID = 2412350)
BEGIN
    UPDATE Users
    SET Username = 'alex_analyst',
        ClearanceTier = 1,
        AccountStatus = 'Active',
        Password = 'Analyst123'
    WHERE UserID = 2412350;
    PRINT '[SUCCESS] Tier 1 Analyst (UserID: 2412350) verified.';
END
ELSE
BEGIN
    INSERT INTO Users (UserID, Username, ClearanceTier, AccountStatus, Password)
    VALUES (2412350, 'alex_analyst', 1, 'Active', 'Analyst123');
    PRINT '[SUCCESS] Tier 1 Analyst (UserID: 2412350) created.';
END
GO

-- 5. Seed 2-3 Realistic Saved Credentials for Each User into User_Vault
-- ------------------------------------------------------------------------------
-- 5a. User 2412348 (balti_admin)
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM User_Vault WHERE UserID = 2412348)
BEGIN
    INSERT INTO User_Vault (UserID, CredentialName, ProtectedSecret, SecurityClassification, LastUpdated)
    VALUES 
    (2412348, 'AWS Production Root Key', 'AKIA5Z7R8QPRODROOTKEY2026', 'Top Secret', GETDATE()),
    (2412348, 'Database Master Password', 'DbMaster#99Secure!VaultKey', 'Top Secret', GETDATE()),
    (2412348, 'Cloudflare Enterprise API Token', 'cf_api_994827103857_prod_shield', 'Confidential', GETDATE());
    PRINT '[SUCCESS] Seeded 3 protected credentials for User 2412348 (Admin).';
END
GO

-- ------------------------------------------------------------------------------
-- 5b. User 2412349 (sarah_operator)
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM User_Vault WHERE UserID = 2412349)
BEGIN
    INSERT INTO User_Vault (UserID, CredentialName, ProtectedSecret, SecurityClassification, LastUpdated)
    VALUES 
    (2412349, 'GitHub Enterprise SSH Token', 'ghp_x99482019482710495837201948', 'Confidential', GETDATE()),
    (2412349, 'Kubernetes Cluster Auth Bearer', 'ey7b9201.k8s.bearer.op_token.v2', 'Restricted', GETDATE()),
    (2412349, 'Internal VPN Access Key', 'VPN-OP-NODE-4491-SECURE-KEY', 'Restricted', GETDATE());
    PRINT '[SUCCESS] Seeded 3 protected credentials for User 2412349 (Operator).';
END
GO

-- ------------------------------------------------------------------------------
-- 5c. User 2412350 (alex_analyst)
-- ------------------------------------------------------------------------------
IF NOT EXISTS (SELECT 1 FROM User_Vault WHERE UserID = 2412350)
BEGIN
    INSERT INTO User_Vault (UserID, CredentialName, ProtectedSecret, SecurityClassification, LastUpdated)
    VALUES 
    (2412350, 'Splunk SIEM Read-Only Token', 'splunk_ro_8839201948572019', 'Confidential', GETDATE()),
    (2412350, 'Network Packet Sniffer Private Key', 'pk_sniff_net_analyst_2026', 'Restricted', GETDATE()),
    (2412350, 'SOC Incident Response Webhook', 'https://soc.vault.internal/wh/alert_771', 'Confidential', GETDATE());
    PRINT '[SUCCESS] Seeded 3 protected credentials for User 2412350 (Analyst).';
END
GO

-- 6. Stored Procedure: Validate_Access (Action: Classified Vault Access)
IF OBJECT_ID('Validate_Access', 'P') IS NOT NULL
    DROP PROCEDURE Validate_Access;
GO

CREATE PROCEDURE Validate_Access
    @UserID INT,
    @AccessGranted BIT OUTPUT,
    @StatusMessage VARCHAR(255) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    DECLARE @Tier INT, @Status VARCHAR(50);
    SELECT @Tier = ClearanceTier, @Status = AccountStatus FROM Users WHERE UserID = @UserID;
    
    IF @Status = 'Active' AND @Tier >= 2
    BEGIN
        SET @AccessGranted = 1;
        SET @StatusMessage = 'ACCESS GRANTED: Clearance Tier ' + CAST(@Tier AS VARCHAR) + ' meets operational authorization threshold (Tier >= 2).';
    END
    ELSE
    BEGIN
        SET @AccessGranted = 0;
        IF @Status != 'Active'
            SET @StatusMessage = 'ACCESS DENIED: Account security status is currently ''' + ISNULL(@Status, 'Unknown') + ''' — Incident Logged to SIEM';
        ELSE
            SET @StatusMessage = 'ACCESS DENIED: Insufficient Clearance Tier ' + CAST(ISNULL(@Tier, 0) AS VARCHAR) + ' — Incident Logged to SIEM';
    END
END;
GO
PRINT '[SUCCESS] Stored Procedure [Validate_Access] compiled successfully.';
GO

-- ==============================================================================
-- 7. Academic / Laboratory Demonstration Scripts
-- ==============================================================================

-- ------------------------------------------------------------------------------
-- DEMO A: Automated Threat Detection Subquery
-- Flags accounts whose failed attempts ('Denied', 'MFA_Failed') exceed the system
-- average clearance tier:
-- ------------------------------------------------------------------------------
SELECT 
    u.Username, 
    COUNT(a.LogID) AS Total_Failed_Attempts 
FROM Users u 
JOIN Audit_Logs a ON u.UserID = a.UserID 
WHERE a.Status IN ('Denied', 'MFA_Failed') 
GROUP BY u.Username 
HAVING COUNT(a.LogID) > (SELECT AVG(ClearanceTier) FROM Users);
GO

-- ------------------------------------------------------------------------------
-- DEMO B: Atomicity Demo (Add & Protect New Credential)
-- Wraps INSERT INTO User_Vault and INSERT INTO Audit_Logs inside a single transaction
-- ------------------------------------------------------------------------------
BEGIN TRANSACTION;
BEGIN TRY
    INSERT INTO User_Vault (UserID, CredentialName, ProtectedSecret, SecurityClassification, LastUpdated)
    VALUES (2412348, 'Stripe Gateway Live Secret', 'sk_live_51M0019284710293847', 'Top Secret', GETDATE());

    INSERT INTO Audit_Logs (UserID, LoginTime, Status)
    VALUES (2412348, GETDATE(), 'Vault_Write');

    COMMIT TRANSACTION;
    PRINT '[ATOMICITY SUCCESS] Vault credential and Audit Log committed atomically.';
END TRY
BEGIN CATCH
    IF @@TRANCOUNT > 0
        ROLLBACK TRANSACTION;
    PRINT '[ATOMICITY ROLLBACK] An error occurred; transaction rolled back completely.';
END CATCH;
GO

-- ------------------------------------------------------------------------------
-- DEMO C: Concurrency & Row-Level Exclusive Lock Simulation (Strict 2PL)
-- Window 1 holds an exclusive lock for 15 seconds to simulate active encryption:
-- ------------------------------------------------------------------------------
/*
-- RUN IN SSMS WINDOW 1:
BEGIN TRANSACTION;
UPDATE User_Vault WITH (ROWLOCK, HOLDLOCK)
SET ProtectedSecret = 'AKIA_NEW_ROTATED_KEY_2026'
WHERE VaultID = 1;
WAITFOR DELAY '00:00:15';
COMMIT TRANSACTION;

-- RUN IN SSMS WINDOW 2 IMMEDIATELY:
-- Notice Window 2 will FREEZE / BLOCK until Window 1 commits, preventing Dirty Reads!
SELECT * FROM User_Vault WHERE VaultID = 1;
*/

-- ------------------------------------------------------------------------------
-- DEMO D: Savepoint & Partial Rollback (MFA Attack Simulation)
-- ------------------------------------------------------------------------------
/*
BEGIN TRANSACTION;
INSERT INTO Audit_Logs (UserID, LoginTime, Status) VALUES (2412350, GETDATE(), 'Pending_MFA');
SAVE TRANSACTION mfa_vault_check;

-- If PIN is invalid:
ROLLBACK TRANSACTION mfa_vault_check; -- Partial rollback preserving outer transaction!
INSERT INTO Audit_Logs (UserID, LoginTime, Status) VALUES (2412350, GETDATE(), 'MFA_Failed');
COMMIT TRANSACTION;
*/

-- ------------------------------------------------------------------------------
-- DEMO E: Cascade-Safe Delete User
-- Purges User_Vault, then Audit_Logs, then Users inside a single transaction
-- ------------------------------------------------------------------------------
/*
BEGIN TRANSACTION;
DELETE FROM User_Vault WHERE UserID = @TargetUserID;
DELETE FROM Audit_Logs WHERE UserID = @TargetUserID;
DELETE FROM Users WHERE UserID = @TargetUserID;
COMMIT TRANSACTION;
*/
