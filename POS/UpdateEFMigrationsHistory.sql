-- Add a record to the migrations history table to mark the CartItems migration as applied
IF EXISTS (SELECT * FROM sys.tables WHERE name = '__EFMigrationsHistory' AND schema_id = SCHEMA_ID('dbo'))
BEGIN
    -- Check if the migration has already been applied
    IF NOT EXISTS (SELECT 1 FROM [__EFMigrationsHistory] WHERE [MigrationId] = '20250419061630_AddCartItemsTable2')
    BEGIN
        -- Add the migration record
        INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
        VALUES ('20250419061630_AddCartItemsTable2', '9.0.3');
        
        PRINT 'Migration record added to __EFMigrationsHistory table';
    END
    ELSE
    BEGIN
        PRINT 'Migration record already exists in __EFMigrationsHistory table';
    END
END
ELSE
BEGIN
    PRINT '__EFMigrationsHistory table does not exist';
END 