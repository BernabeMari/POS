-- Script to check and fix the CartItems table

-- Check if the CartItems table exists and its structure
IF EXISTS (SELECT * FROM sys.tables WHERE name = 'CartItems' AND schema_id = SCHEMA_ID('dbo'))
BEGIN
    PRINT 'CartItems table exists, checking structure...';
    
    -- Check ProductImageDescription column and modify it if needed
    IF EXISTS (SELECT * FROM sys.columns WHERE Name = 'ProductImageDescription' AND Object_ID = Object_ID('CartItems'))
    BEGIN
        -- Check if it allows nulls but shouldn't
        DECLARE @IsNullable int
        SELECT @IsNullable = is_nullable FROM sys.columns WHERE Name = 'ProductImageDescription' AND Object_ID = Object_ID('CartItems')
        
        IF @IsNullable = 1
        BEGIN
            PRINT 'Fixing ProductImageDescription column to NOT NULL with default value';
            -- First update any NULL values
            UPDATE CartItems SET ProductImageDescription = ProductName WHERE ProductImageDescription IS NULL;
            -- Then alter the column
            ALTER TABLE CartItems ALTER COLUMN ProductImageDescription nvarchar(500) NOT NULL;
        END
        ELSE
        BEGIN
            PRINT 'ProductImageDescription column is already NOT NULL';
        END
    END
    ELSE
    BEGIN
        PRINT 'Adding missing ProductImageDescription column';
        ALTER TABLE CartItems ADD ProductImageDescription nvarchar(500) NOT NULL DEFAULT '';
    END
    
    -- Check if the UserId foreign key exists
    IF NOT EXISTS (
        SELECT * FROM sys.foreign_keys 
        WHERE name = 'FK_CartItems_AspNetUsers_UserId' AND parent_object_id = OBJECT_ID('CartItems')
    )
    BEGIN
        PRINT 'Adding missing foreign key constraint to UserId';
        ALTER TABLE [dbo].[CartItems] WITH CHECK ADD CONSTRAINT [FK_CartItems_AspNetUsers_UserId] 
        FOREIGN KEY([UserId]) REFERENCES [dbo].[AspNetUsers] ([Id]) ON DELETE CASCADE;
    END
    ELSE
    BEGIN
        PRINT 'UserId foreign key exists';
    END
    
    -- Check if index exists
    IF NOT EXISTS (
        SELECT * FROM sys.indexes 
        WHERE name = 'IX_CartItems_UserId' AND object_id = OBJECT_ID('CartItems')
    )
    BEGIN
        PRINT 'Adding missing index on UserId';
        CREATE NONCLUSTERED INDEX [IX_CartItems_UserId] ON [dbo].[CartItems] ([UserId]);
    END
    ELSE
    BEGIN
        PRINT 'UserId index exists';
    END
    
    -- Check CreatedAt and UpdatedAt column types
    DECLARE @CreatedAtType nvarchar(128)
    SELECT @CreatedAtType = DATA_TYPE 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = 'CartItems' AND COLUMN_NAME = 'CreatedAt'
    
    IF @CreatedAtType <> 'datetime2'
    BEGIN
        PRINT 'Fixing CreatedAt column type to datetime2';
        ALTER TABLE CartItems ALTER COLUMN CreatedAt datetime2(7) NOT NULL;
    END
    
    DECLARE @UpdatedAtType nvarchar(128)
    SELECT @UpdatedAtType = DATA_TYPE 
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = 'CartItems' AND COLUMN_NAME = 'UpdatedAt'
    
    IF @UpdatedAtType <> 'datetime2'
    BEGIN
        PRINT 'Fixing UpdatedAt column type to datetime2';
        ALTER TABLE CartItems ALTER COLUMN UpdatedAt datetime2(7) NULL;
    END
    
    -- Check Price column decimal precision
    DECLARE @PriceScale int
    SELECT @PriceScale = NUMERIC_SCALE
    FROM INFORMATION_SCHEMA.COLUMNS 
    WHERE TABLE_NAME = 'CartItems' AND COLUMN_NAME = 'Price'
    
    IF @PriceScale <> 2
    BEGIN
        PRINT 'Fixing Price column decimal precision to (18,2)';
        ALTER TABLE CartItems ALTER COLUMN Price decimal(18,2) NOT NULL;
    END
    
    PRINT 'CartItems table check and fix completed';
END
ELSE
BEGIN
    PRINT 'CartItems table does not exist! Creating it...';
    
    -- Create CartItems table
    CREATE TABLE [dbo].[CartItems](
        [Id] [int] IDENTITY(1,1) NOT NULL,
        [UserId] [nvarchar](450) NOT NULL,
        [ProductId] [int] NULL,
        [ProductName] [nvarchar](max) NOT NULL,
        [ProductImageUrl] [nvarchar](max) NOT NULL,
        [ProductImageDescription] [nvarchar](500) NOT NULL,
        [Price] [decimal](18, 2) NOT NULL,
        [Quantity] [int] NOT NULL,
        [CreatedAt] [datetime2](7) NOT NULL,
        [UpdatedAt] [datetime2](7) NULL,
        CONSTRAINT [PK_CartItems] PRIMARY KEY CLUSTERED ([Id] ASC)
    );

    -- Add foreign key constraint
    ALTER TABLE [dbo].[CartItems] WITH CHECK ADD CONSTRAINT [FK_CartItems_AspNetUsers_UserId] 
    FOREIGN KEY([UserId]) REFERENCES [dbo].[AspNetUsers] ([Id]) ON DELETE CASCADE;

    -- Create index on UserId for faster lookups
    CREATE NONCLUSTERED INDEX [IX_CartItems_UserId] ON [dbo].[CartItems] ([UserId]);
    
    PRINT 'CartItems table created successfully';
END 