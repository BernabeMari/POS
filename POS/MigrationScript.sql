IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
BEGIN
    CREATE TABLE [__EFMigrationsHistory] (
        [MigrationId] nvarchar(150) NOT NULL,
        [ProductVersion] nvarchar(32) NOT NULL,
        CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
    );
END;
GO

BEGIN TRANSACTION;
CREATE TABLE [AspNetRoles] (
    [Id] nvarchar(450) NOT NULL,
    [Name] nvarchar(256) NULL,
    [NormalizedName] nvarchar(256) NULL,
    [ConcurrencyStamp] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetRoles] PRIMARY KEY ([Id])
);

CREATE TABLE [AspNetUsers] (
    [Id] nvarchar(450) NOT NULL,
    [FullName] nvarchar(max) NOT NULL,
    [IsAdmin] bit NOT NULL,
    [CreatedAt] datetime2 NOT NULL,
    [UserName] nvarchar(256) NULL,
    [NormalizedUserName] nvarchar(256) NULL,
    [Email] nvarchar(256) NULL,
    [NormalizedEmail] nvarchar(256) NULL,
    [EmailConfirmed] bit NOT NULL,
    [PasswordHash] nvarchar(max) NULL,
    [SecurityStamp] nvarchar(max) NULL,
    [ConcurrencyStamp] nvarchar(max) NULL,
    [PhoneNumber] nvarchar(max) NULL,
    [PhoneNumberConfirmed] bit NOT NULL,
    [TwoFactorEnabled] bit NOT NULL,
    [LockoutEnd] datetimeoffset NULL,
    [LockoutEnabled] bit NOT NULL,
    [AccessFailedCount] int NOT NULL,
    CONSTRAINT [PK_AspNetUsers] PRIMARY KEY ([Id])
);

CREATE TABLE [PageTemplates] (
    [Id] int NOT NULL IDENTITY,
    [Name] nvarchar(max) NOT NULL,
    [Description] nvarchar(max) NOT NULL,
    [BackgroundColor] nvarchar(max) NOT NULL,
    [HeaderColor] nvarchar(max) NOT NULL,
    [FooterColor] nvarchar(max) NOT NULL,
    [IsActive] bit NOT NULL,
    [CreatedAt] datetime2 NOT NULL,
    [LastModified] datetime2 NULL,
    CONSTRAINT [PK_PageTemplates] PRIMARY KEY ([Id])
);

CREATE TABLE [AspNetRoleClaims] (
    [Id] int NOT NULL IDENTITY,
    [RoleId] nvarchar(450) NOT NULL,
    [ClaimType] nvarchar(max) NULL,
    [ClaimValue] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetRoleClaims] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId] FOREIGN KEY ([RoleId]) REFERENCES [AspNetRoles] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [AspNetUserClaims] (
    [Id] int NOT NULL IDENTITY,
    [UserId] nvarchar(450) NOT NULL,
    [ClaimType] nvarchar(max) NULL,
    [ClaimValue] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetUserClaims] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [AspNetUserLogins] (
    [LoginProvider] nvarchar(450) NOT NULL,
    [ProviderKey] nvarchar(450) NOT NULL,
    [ProviderDisplayName] nvarchar(max) NULL,
    [UserId] nvarchar(450) NOT NULL,
    CONSTRAINT [PK_AspNetUserLogins] PRIMARY KEY ([LoginProvider], [ProviderKey]),
    CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [AspNetUserRoles] (
    [UserId] nvarchar(450) NOT NULL,
    [RoleId] nvarchar(450) NOT NULL,
    CONSTRAINT [PK_AspNetUserRoles] PRIMARY KEY ([UserId], [RoleId]),
    CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId] FOREIGN KEY ([RoleId]) REFERENCES [AspNetRoles] ([Id]) ON DELETE CASCADE,
    CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [AspNetUserTokens] (
    [UserId] nvarchar(450) NOT NULL,
    [LoginProvider] nvarchar(450) NOT NULL,
    [Name] nvarchar(450) NOT NULL,
    [Value] nvarchar(max) NULL,
    CONSTRAINT [PK_AspNetUserTokens] PRIMARY KEY ([UserId], [LoginProvider], [Name]),
    CONSTRAINT [FK_AspNetUserTokens_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [PageElements] (
    [Id] int NOT NULL IDENTITY,
    [PageName] nvarchar(max) NOT NULL,
    [ElementType] nvarchar(max) NOT NULL,
    [ElementId] nvarchar(max) NOT NULL,
    [Text] nvarchar(max) NOT NULL,
    [Color] nvarchar(max) NOT NULL,
    [PositionX] int NOT NULL,
    [PositionY] int NOT NULL,
    [Width] int NOT NULL,
    [Height] int NOT NULL,
    [AdditionalStyles] nvarchar(max) NOT NULL,
    [IsVisible] bit NOT NULL,
    [LastModified] datetime2 NOT NULL,
    [PageTemplateId] int NULL,
    CONSTRAINT [PK_PageElements] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_PageElements_PageTemplates_PageTemplateId] FOREIGN KEY ([PageTemplateId]) REFERENCES [PageTemplates] ([Id]) ON DELETE CASCADE
);

CREATE INDEX [IX_AspNetRoleClaims_RoleId] ON [AspNetRoleClaims] ([RoleId]);

CREATE UNIQUE INDEX [RoleNameIndex] ON [AspNetRoles] ([NormalizedName]) WHERE [NormalizedName] IS NOT NULL;

CREATE INDEX [IX_AspNetUserClaims_UserId] ON [AspNetUserClaims] ([UserId]);

CREATE INDEX [IX_AspNetUserLogins_UserId] ON [AspNetUserLogins] ([UserId]);

CREATE INDEX [IX_AspNetUserRoles_RoleId] ON [AspNetUserRoles] ([RoleId]);

CREATE INDEX [EmailIndex] ON [AspNetUsers] ([NormalizedEmail]);

CREATE UNIQUE INDEX [UserNameIndex] ON [AspNetUsers] ([NormalizedUserName]) WHERE [NormalizedUserName] IS NOT NULL;

CREATE INDEX [IX_PageElements_PageTemplateId] ON [PageElements] ([PageTemplateId]);

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250330081714_AddFullNameToApplicationUser', N'9.0.4');

ALTER TABLE [PageElements] ADD [ImageDescription] nvarchar(max) NOT NULL DEFAULT N'';

ALTER TABLE [PageElements] ADD [ImageUrl] nvarchar(max) NOT NULL DEFAULT N'';

ALTER TABLE [AspNetUsers] ADD [IsEmployee] bit NOT NULL DEFAULT CAST(0 AS bit);

ALTER TABLE [AspNetUsers] ADD [PositionId] int NULL;

CREATE TABLE [AspUserPositions] (
    [Id] int NOT NULL IDENTITY,
    [Name] nvarchar(50) NOT NULL,
    [Description] nvarchar(255) NOT NULL,
    [CreatedAt] datetime2 NOT NULL,
    [IsActive] bit NOT NULL,
    CONSTRAINT [PK_AspUserPositions] PRIMARY KEY ([Id])
);

CREATE TABLE [LoginSettings] (
    [Id] int NOT NULL IDENTITY,
    [MaxLoginAttempts] int NOT NULL,
    [LockoutDuration] int NOT NULL,
    [EnableLockout] bit NOT NULL,
    [LastUpdated] datetime2 NOT NULL,
    [UpdatedBy] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_LoginSettings] PRIMARY KEY ([Id])
);

CREATE TABLE [Orders] (
    [Id] int NOT NULL IDENTITY,
    [UserId] nvarchar(450) NOT NULL,
    [AssignedToEmployeeId] nvarchar(450) NULL,
    [ProductName] nvarchar(max) NOT NULL,
    [ProductImageUrl] nvarchar(max) NOT NULL,
    [Price] decimal(18,2) NOT NULL,
    [Quantity] int NOT NULL,
    [Notes] nvarchar(500) NOT NULL,
    [CreatedAt] datetime2 NOT NULL,
    [UpdatedAt] datetime2 NULL,
    [Status] int NOT NULL,
    CONSTRAINT [PK_Orders] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_Orders_AspNetUsers_AssignedToEmployeeId] FOREIGN KEY ([AssignedToEmployeeId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE SET NULL,
    CONSTRAINT [FK_Orders_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE NO ACTION
);

CREATE TABLE [PageElementImages] (
    [Id] int NOT NULL IDENTITY,
    [PageElementId] int NOT NULL,
    [Base64Data] nvarchar(max) NOT NULL,
    [Description] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_PageElementImages] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_PageElementImages_PageElements_PageElementId] FOREIGN KEY ([PageElementId]) REFERENCES [PageElements] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [Products] (
    [Id] int NOT NULL IDENTITY,
    [Name] nvarchar(100) NOT NULL,
    [Description] nvarchar(500) NOT NULL,
    [Price] decimal(18,2) NOT NULL,
    [ImageUrl] nvarchar(max) NOT NULL,
    [IsAvailable] bit NOT NULL,
    [StockQuantity] int NOT NULL,
    [CreatedAt] datetime2 NOT NULL,
    [UpdatedAt] datetime2 NULL,
    CONSTRAINT [PK_Products] PRIMARY KEY ([Id])
);

CREATE INDEX [IX_AspNetUsers_PositionId] ON [AspNetUsers] ([PositionId]);

CREATE INDEX [IX_Orders_AssignedToEmployeeId] ON [Orders] ([AssignedToEmployeeId]);

CREATE INDEX [IX_Orders_UserId] ON [Orders] ([UserId]);

CREATE INDEX [IX_PageElementImages_PageElementId] ON [PageElementImages] ([PageElementId]);

ALTER TABLE [AspNetUsers] ADD CONSTRAINT [FK_AspNetUsers_AspUserPositions_PositionId] FOREIGN KEY ([PositionId]) REFERENCES [AspUserPositions] ([Id]) ON DELETE SET NULL;

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250331145323_AddNewOrderStatuses', N'9.0.4');

ALTER TABLE [Orders] ADD [ProductImageDescription] nvarchar(500) NOT NULL DEFAULT N'';

ALTER TABLE [Orders] ADD [TotalPrice] decimal(18,2) NOT NULL DEFAULT 0.0;

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250331151642_AddOrderImageFields', N'9.0.4');

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250331151825_ConfigurePrecisionForDecimalFields', N'9.0.4');

ALTER TABLE [Products] ADD [ImageDescription] nvarchar(500) NOT NULL DEFAULT N'';

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250331152404_AddProductImageDescription', N'9.0.4');

ALTER TABLE [PageElements] ADD [IsProduct] bit NOT NULL DEFAULT CAST(0 AS bit);

ALTER TABLE [PageElements] ADD [ProductDescription] nvarchar(max) NOT NULL DEFAULT N'';

ALTER TABLE [PageElements] ADD [ProductName] nvarchar(max) NOT NULL DEFAULT N'';

ALTER TABLE [PageElements] ADD [ProductPrice] decimal(18,2) NOT NULL DEFAULT 0.0;

ALTER TABLE [PageElements] ADD [ProductStockQuantity] int NOT NULL DEFAULT 0;

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250331153722_AddProductFieldsToPageElement', N'9.0.4');

DECLARE @var sysname;
SELECT @var = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Products]') AND [c].[name] = N'ImageUrl');
IF @var IS NOT NULL EXEC(N'ALTER TABLE [Products] DROP CONSTRAINT [' + @var + '];');
ALTER TABLE [Products] ALTER COLUMN [ImageUrl] nvarchar(255) NOT NULL;

DECLARE @var1 sysname;
SELECT @var1 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Products]') AND [c].[name] = N'ImageDescription');
IF @var1 IS NOT NULL EXEC(N'ALTER TABLE [Products] DROP CONSTRAINT [' + @var1 + '];');
ALTER TABLE [Products] ALTER COLUMN [ImageDescription] nvarchar(255) NOT NULL;

ALTER TABLE [Products] ADD [CategoryId] int NOT NULL DEFAULT 0;

ALTER TABLE [Products] ADD [ReorderThreshold] int NOT NULL DEFAULT 0;

ALTER TABLE [Products] ADD [Unit] nvarchar(20) NOT NULL DEFAULT N'';

CREATE TABLE [Categories] (
    [Id] int NOT NULL IDENTITY,
    [Name] nvarchar(50) NOT NULL,
    [Description] nvarchar(200) NOT NULL,
    CONSTRAINT [PK_Categories] PRIMARY KEY ([Id])
);

CREATE TABLE [InventoryLogs] (
    [Id] int NOT NULL IDENTITY,
    [ProductId] int NOT NULL,
    [PreviousQuantity] int NOT NULL,
    [NewQuantity] int NOT NULL,
    [ChangeReason] nvarchar(50) NOT NULL,
    [Notes] nvarchar(500) NOT NULL,
    [UserId] nvarchar(450) NOT NULL,
    [Timestamp] datetime2 NOT NULL,
    CONSTRAINT [PK_InventoryLogs] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_InventoryLogs_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE,
    CONSTRAINT [FK_InventoryLogs_Products_ProductId] FOREIGN KEY ([ProductId]) REFERENCES [Products] ([Id]) ON DELETE CASCADE
);

CREATE INDEX [IX_Products_CategoryId] ON [Products] ([CategoryId]);

CREATE INDEX [IX_InventoryLogs_ProductId] ON [InventoryLogs] ([ProductId]);

CREATE INDEX [IX_InventoryLogs_UserId] ON [InventoryLogs] ([UserId]);

ALTER TABLE [Products] ADD CONSTRAINT [FK_Products_Categories_CategoryId] FOREIGN KEY ([CategoryId]) REFERENCES [Categories] ([Id]) ON DELETE CASCADE;

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250413074824_InitializeDatabase', N'9.0.4');

CREATE TABLE [Stocks] (
    [StockID] int NOT NULL IDENTITY,
    [ProductName] nvarchar(100) NOT NULL,
    [Category] nvarchar(50) NOT NULL,
    [Quantity] decimal(10,2) NOT NULL,
    [UnitType] nvarchar(20) NOT NULL,
    [ThresholdLevel] decimal(10,2) NOT NULL,
    [LastUpdated] datetime2 NOT NULL,
    [UpdatedBy] nvarchar(max) NOT NULL,
    [Notes] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_Stocks] PRIMARY KEY ([StockID])
);

CREATE TABLE [StockHistory] (
    [HistoryID] int NOT NULL IDENTITY,
    [StockID] int NOT NULL,
    [PreviousQuantity] decimal(10,2) NOT NULL,
    [NewQuantity] decimal(10,2) NOT NULL,
    [ChangeReason] nvarchar(50) NOT NULL,
    [ChangedBy] nvarchar(max) NOT NULL,
    [ChangeDate] datetime2 NOT NULL,
    [Notes] nvarchar(max) NOT NULL,
    CONSTRAINT [PK_StockHistory] PRIMARY KEY ([HistoryID]),
    CONSTRAINT [FK_StockHistory_Stocks_StockID] FOREIGN KEY ([StockID]) REFERENCES [Stocks] ([StockID]) ON DELETE CASCADE
);

CREATE INDEX [IX_StockHistory_StockID] ON [StockHistory] ([StockID]);

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250413081404_AddStockTables', N'9.0.4');

DECLARE @var2 sysname;
SELECT @var2 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Stocks]') AND [c].[name] = N'UpdatedBy');
IF @var2 IS NOT NULL EXEC(N'ALTER TABLE [Stocks] DROP CONSTRAINT [' + @var2 + '];');
ALTER TABLE [Stocks] ALTER COLUMN [UpdatedBy] nvarchar(max) NULL;

DECLARE @var3 sysname;
SELECT @var3 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[Stocks]') AND [c].[name] = N'Notes');
IF @var3 IS NOT NULL EXEC(N'ALTER TABLE [Stocks] DROP CONSTRAINT [' + @var3 + '];');
ALTER TABLE [Stocks] ALTER COLUMN [Notes] nvarchar(max) NULL;

DECLARE @var4 sysname;
SELECT @var4 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[StockHistory]') AND [c].[name] = N'Notes');
IF @var4 IS NOT NULL EXEC(N'ALTER TABLE [StockHistory] DROP CONSTRAINT [' + @var4 + '];');
ALTER TABLE [StockHistory] ALTER COLUMN [Notes] nvarchar(max) NULL;

DECLARE @var5 sysname;
SELECT @var5 = [d].[name]
FROM [sys].[default_constraints] [d]
INNER JOIN [sys].[columns] [c] ON [d].[parent_column_id] = [c].[column_id] AND [d].[parent_object_id] = [c].[object_id]
WHERE ([d].[parent_object_id] = OBJECT_ID(N'[StockHistory]') AND [c].[name] = N'ChangedBy');
IF @var5 IS NOT NULL EXEC(N'ALTER TABLE [StockHistory] DROP CONSTRAINT [' + @var5 + '];');
ALTER TABLE [StockHistory] ALTER COLUMN [ChangedBy] nvarchar(max) NULL;

ALTER TABLE [AspNetUsers] ADD [LastWalletTopUp] datetime2 NOT NULL DEFAULT '0001-01-01T00:00:00.0000000';

ALTER TABLE [AspNetUsers] ADD [WalletBalance] decimal(18,2) NOT NULL DEFAULT 0.0;

CREATE TABLE [CartItems] (
    [Id] int NOT NULL IDENTITY,
    [UserId] nvarchar(450) NOT NULL,
    [ProductId] int NULL,
    [ProductName] nvarchar(max) NOT NULL,
    [ProductImageUrl] nvarchar(max) NOT NULL,
    [ProductImageDescription] nvarchar(500) NOT NULL,
    [Price] decimal(18,2) NOT NULL,
    [Quantity] int NOT NULL,
    [CreatedAt] datetime2 NOT NULL,
    [UpdatedAt] datetime2 NULL,
    CONSTRAINT [PK_CartItems] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_CartItems_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [Wallets] (
    [Id] int NOT NULL IDENTITY,
    [UserId] nvarchar(450) NOT NULL,
    [Balance] decimal(18,2) NOT NULL,
    [CreatedAt] datetime2 NOT NULL,
    [UpdatedAt] datetime2 NULL,
    CONSTRAINT [PK_Wallets] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_Wallets_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
);

CREATE TABLE [WalletTransactions] (
    [Id] int NOT NULL IDENTITY,
    [UserId] nvarchar(450) NOT NULL,
    [Timestamp] datetime2 NOT NULL,
    [Amount] decimal(18,2) NOT NULL,
    [Type] int NOT NULL,
    [ReferenceNumber] nvarchar(50) NOT NULL,
    [Description] nvarchar(255) NOT NULL,
    [OrderId] int NULL,
    [PreviousBalance] decimal(18,2) NOT NULL,
    [NewBalance] decimal(18,2) NOT NULL,
    [WalletId] int NOT NULL,
    CONSTRAINT [PK_WalletTransactions] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_WalletTransactions_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE NO ACTION,
    CONSTRAINT [FK_WalletTransactions_Orders_OrderId] FOREIGN KEY ([OrderId]) REFERENCES [Orders] ([Id]),
    CONSTRAINT [FK_WalletTransactions_Wallets_WalletId] FOREIGN KEY ([WalletId]) REFERENCES [Wallets] ([Id]) ON DELETE CASCADE
);

CREATE INDEX [IX_CartItems_UserId] ON [CartItems] ([UserId]);

CREATE INDEX [IX_Wallets_UserId] ON [Wallets] ([UserId]);

CREATE INDEX [IX_WalletTransactions_OrderId] ON [WalletTransactions] ([OrderId]);

CREATE INDEX [IX_WalletTransactions_UserId] ON [WalletTransactions] ([UserId]);

CREATE INDEX [IX_WalletTransactions_WalletId] ON [WalletTransactions] ([WalletId]);

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250419061630_AddCartItemsTable2', N'9.0.4');

ALTER TABLE [AspNetUsers] ADD [IsPWD] bit NOT NULL DEFAULT CAST(0 AS bit);

ALTER TABLE [AspNetUsers] ADD [IsSeniorCitizen] bit NOT NULL DEFAULT CAST(0 AS bit);

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250419131521_AddSeniorPwdFields', N'9.0.4');

ALTER TABLE [Orders] ADD [DiscountAmount] decimal(18,2) NOT NULL DEFAULT 0.0;

ALTER TABLE [Orders] ADD [DiscountApprovedById] nvarchar(450) NULL;

ALTER TABLE [Orders] ADD [DiscountPercentage] decimal(18,2) NOT NULL DEFAULT 0.0;

ALTER TABLE [Orders] ADD [DiscountType] nvarchar(max) NULL;

ALTER TABLE [Orders] ADD [IsDiscountApproved] bit NOT NULL DEFAULT CAST(0 AS bit);

ALTER TABLE [Orders] ADD [IsDiscountRequested] bit NOT NULL DEFAULT CAST(0 AS bit);

ALTER TABLE [Orders] ADD [OriginalTotalPrice] decimal(18,2) NOT NULL DEFAULT 0.0;

CREATE TABLE [ProductIngredients] (
    [Id] int NOT NULL IDENTITY,
    [PageElementId] int NOT NULL,
    [IngredientName] nvarchar(100) NOT NULL,
    [Quantity] decimal(18,2) NOT NULL,
    [Unit] nvarchar(20) NOT NULL,
    [Notes] nvarchar(255) NOT NULL,
    CONSTRAINT [PK_ProductIngredients] PRIMARY KEY ([Id]),
    CONSTRAINT [FK_ProductIngredients_PageElements_PageElementId] FOREIGN KEY ([PageElementId]) REFERENCES [PageElements] ([Id]) ON DELETE CASCADE
);

CREATE INDEX [IX_Orders_DiscountApprovedById] ON [Orders] ([DiscountApprovedById]);

CREATE INDEX [IX_ProductIngredients_PageElementId] ON [ProductIngredients] ([PageElementId]);

ALTER TABLE [Orders] ADD CONSTRAINT [FK_Orders_AspNetUsers_DiscountApprovedById] FOREIGN KEY ([DiscountApprovedById]) REFERENCES [AspNetUsers] ([Id]);

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250420042727_AddProductIngredients', N'9.0.4');

ALTER TABLE [PageElements] ADD [IsAvailable] bit NOT NULL DEFAULT CAST(0 AS bit);

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250428172713_InitialCreate', N'9.0.4');

COMMIT;
GO

