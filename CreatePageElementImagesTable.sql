-- Create PageElementImages table if it doesn't exist
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'PageElementImages')
BEGIN
    CREATE TABLE [dbo].[PageElementImages](
        [Id] [int] IDENTITY(1,1) NOT NULL,
        [PageElementId] [int] NOT NULL,
        [Base64Data] [nvarchar](max) NOT NULL,
        [Description] [nvarchar](max) NOT NULL,
        CONSTRAINT [PK_PageElementImages] PRIMARY KEY CLUSTERED ([Id] ASC)
    );

    -- Add foreign key constraint
    ALTER TABLE [dbo].[PageElementImages] 
    ADD CONSTRAINT [FK_PageElementImages_PageElements_PageElementId] 
    FOREIGN KEY([PageElementId]) REFERENCES [dbo].[PageElements] ([Id]) ON DELETE CASCADE;

    -- Create index
    CREATE INDEX [IX_PageElementImages_PageElementId] 
    ON [dbo].[PageElementImages]([PageElementId]);

    PRINT 'PageElementImages table created successfully.';
END
ELSE
BEGIN
    PRINT 'PageElementImages table already exists.';
END 