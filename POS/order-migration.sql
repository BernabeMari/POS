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
VALUES (N'20250330081714_AddFullNameToApplicationUser', N'9.0.3');

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
VALUES (N'20250331145323_AddNewOrderStatuses', N'9.0.3');

ALTER TABLE [Orders] ADD [ProductImageDescription] nvarchar(500) NOT NULL DEFAULT N'';

ALTER TABLE [Orders] ADD [TotalPrice] decimal(18,2) NOT NULL DEFAULT 0.0;

INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
VALUES (N'20250331151642_AddOrderImageFields', N'9.0.3');

COMMIT;
GO

