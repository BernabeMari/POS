-- Check if AspUserPositions table exists and create it if not
IF NOT EXISTS (SELECT * FROM sys.tables WHERE name = 'AspUserPositions')
BEGIN
    CREATE TABLE [AspUserPositions] (
        [Id] int NOT NULL IDENTITY,
        [Name] nvarchar(50) NOT NULL,
        [Description] nvarchar(255) NULL,
        [CreatedAt] datetime2 NOT NULL,
        [IsActive] bit NOT NULL,
        CONSTRAINT [PK_AspUserPositions] PRIMARY KEY ([Id])
    );
END

-- Update the ApplicationUser table to add new columns if they don't exist
IF NOT EXISTS(SELECT 1 FROM sys.columns WHERE Name = 'IsEmployee' AND Object_ID = Object_ID('AspNetUsers'))
BEGIN
    ALTER TABLE [AspNetUsers] ADD [IsEmployee] bit NOT NULL DEFAULT 0;
END

IF NOT EXISTS(SELECT 1 FROM sys.columns WHERE Name = 'PositionId' AND Object_ID = Object_ID('AspNetUsers'))
BEGIN
    ALTER TABLE [AspNetUsers] ADD [PositionId] int NULL;
END

-- Add foreign key constraint if it doesn't exist
IF NOT EXISTS (SELECT * FROM sys.foreign_keys WHERE object_id = OBJECT_ID(N'[dbo].[FK_AspNetUsers_AspUserPositions_PositionId]') AND parent_object_id = OBJECT_ID(N'[dbo].[AspNetUsers]'))
BEGIN
    ALTER TABLE [AspNetUsers] ADD CONSTRAINT [FK_AspNetUsers_AspUserPositions_PositionId] 
        FOREIGN KEY ([PositionId]) REFERENCES [AspUserPositions] ([Id]) ON DELETE SET NULL;
END

-- Create index for PositionId if it doesn't exist
IF NOT EXISTS(SELECT * FROM sys.indexes WHERE name='IX_AspNetUsers_PositionId' AND object_id = OBJECT_ID('AspNetUsers'))
BEGIN
    CREATE INDEX [IX_AspNetUsers_PositionId] ON [AspNetUsers] ([PositionId]);
END

-- Insert default positions if they don't exist
IF NOT EXISTS (SELECT * FROM [AspUserPositions] WHERE [Name] = 'Manager')
BEGIN
    INSERT INTO [AspUserPositions] ([Name], [Description], [CreatedAt], [IsActive])
    VALUES ('Manager', 'Store manager with full access to management features', GETDATE(), 1);
END

IF NOT EXISTS (SELECT * FROM [AspUserPositions] WHERE [Name] = 'Assistant Manager')
BEGIN
    INSERT INTO [AspUserPositions] ([Name], [Description], [CreatedAt], [IsActive])
    VALUES ('Assistant Manager', 'Reports to the manager and handles day-to-day operations', GETDATE(), 1);
END

IF NOT EXISTS (SELECT * FROM [AspUserPositions] WHERE [Name] = 'Cashier')
BEGIN
    INSERT INTO [AspUserPositions] ([Name], [Description], [CreatedAt], [IsActive])
    VALUES ('Cashier', 'Processes customer transactions', GETDATE(), 1);
END

IF NOT EXISTS (SELECT * FROM [AspUserPositions] WHERE [Name] = 'Inventory Clerk')
BEGIN
    INSERT INTO [AspUserPositions] ([Name], [Description], [CreatedAt], [IsActive])
    VALUES ('Inventory Clerk', 'Manages stock and inventory', GETDATE(), 1);
END

-- Create Employee role if it doesn't exist
IF NOT EXISTS (SELECT * FROM [AspNetRoles] WHERE [Name] = 'Employee')
BEGIN
    DECLARE @RoleId nvarchar(450) = NEWID();
    INSERT INTO [AspNetRoles] ([Id], [Name], [NormalizedName], [ConcurrencyStamp])
    VALUES (@RoleId, 'Employee', 'EMPLOYEE', NEWID());
END 