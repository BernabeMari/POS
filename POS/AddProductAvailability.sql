-- Check if the column exists before adding it
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PageElements' AND COLUMN_NAME = 'IsAvailable')
BEGIN
    ALTER TABLE PageElements ADD IsAvailable bit NOT NULL DEFAULT 1;
END

-- Add this to migrations history if needed
IF NOT EXISTS (SELECT * FROM __EFMigrationsHistory WHERE MigrationId = '20250405123000_AddIsAvailableToPageElements')
BEGIN
    INSERT INTO __EFMigrationsHistory (MigrationId, ProductVersion)
    VALUES ('20250405123000_AddIsAvailableToPageElements', '9.0.3');
END 