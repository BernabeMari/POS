-- Check if the table already exists
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'CartItems' AND schema_id = SCHEMA_ID('dbo'))
BEGIN
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
ELSE
BEGIN
    PRINT 'CartItems table already exists';
END 