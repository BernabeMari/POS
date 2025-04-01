-- Check if columns exist before adding them
IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PageElements' AND COLUMN_NAME = 'IsProduct')
BEGIN
    ALTER TABLE PageElements ADD IsProduct bit NOT NULL DEFAULT 0;
END

IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PageElements' AND COLUMN_NAME = 'ProductName')
BEGIN
    ALTER TABLE PageElements ADD ProductName nvarchar(max) NOT NULL DEFAULT '';
END

IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PageElements' AND COLUMN_NAME = 'ProductDescription')
BEGIN
    ALTER TABLE PageElements ADD ProductDescription nvarchar(max) NOT NULL DEFAULT '';
END

IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PageElements' AND COLUMN_NAME = 'ProductPrice')
BEGIN
    ALTER TABLE PageElements ADD ProductPrice decimal(18,2) NOT NULL DEFAULT 0;
END

IF NOT EXISTS (SELECT * FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = 'PageElements' AND COLUMN_NAME = 'ProductStockQuantity')
BEGIN
    ALTER TABLE PageElements ADD ProductStockQuantity int NOT NULL DEFAULT 0;
END

-- Add this to migrations history if needed
IF NOT EXISTS (SELECT * FROM __EFMigrationsHistory WHERE MigrationId = '20250331155000_AddProductFieldsToPageElement')
BEGIN
    INSERT INTO __EFMigrationsHistory (MigrationId, ProductVersion)
    VALUES ('20250331155000_AddProductFieldsToPageElement', '9.0.3');
END 