-- Script to add FullName column to AspNetUsers table
SET QUOTED_IDENTIFIER ON;
BEGIN TRANSACTION;

-- Check if FullName column exists, add it if it doesn't
IF NOT EXISTS (
    SELECT * 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = 'AspNetUsers' 
    AND COLUMN_NAME = 'FullName'
)
BEGIN
    -- Add the FullName column with a default empty string
    ALTER TABLE AspNetUsers
    ADD FullName nvarchar(max) NOT NULL DEFAULT '';
    
    PRINT 'FullName column added to AspNetUsers table.';
END
ELSE
BEGIN
    PRINT 'FullName column already exists in AspNetUsers table.';
END

-- Check if record exists in EFMigrationsHistory, add it if it doesn't
IF NOT EXISTS (
    SELECT * 
    FROM __EFMigrationsHistory
    WHERE MigrationId = '20250330081714_AddFullNameToApplicationUser'
)
BEGIN
    INSERT INTO __EFMigrationsHistory (MigrationId, ProductVersion)
    VALUES ('20250330081714_AddFullNameToApplicationUser', '9.0.3');
    
    PRINT 'Migration record added to __EFMigrationsHistory.';
END
ELSE
BEGIN
    PRINT 'Migration record already exists in __EFMigrationsHistory.';
END

COMMIT; 