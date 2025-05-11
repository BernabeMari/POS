-- Add discount columns to Orders table
ALTER TABLE Orders
ADD IsDiscountRequested BIT NOT NULL DEFAULT 0;

ALTER TABLE Orders
ADD IsDiscountApproved BIT NOT NULL DEFAULT 0;

ALTER TABLE Orders
ADD DiscountType NVARCHAR(50) NULL;

ALTER TABLE Orders
ADD DiscountPercentage DECIMAL(18,2) NOT NULL DEFAULT 0;

ALTER TABLE Orders
ADD DiscountAmount DECIMAL(18,2) NOT NULL DEFAULT 0;

ALTER TABLE Orders
ADD OriginalTotalPrice DECIMAL(18,2) NOT NULL DEFAULT 0;

ALTER TABLE Orders
ADD DiscountApprovedById NVARCHAR(450) NULL;

-- Create foreign key reference for DiscountApprovedBy
ALTER TABLE Orders
ADD CONSTRAINT FK_Orders_DiscountApprovedBy FOREIGN KEY (DiscountApprovedById)
REFERENCES AspNetUsers (Id) ON DELETE NO ACTION;

-- Update OrderStatus enum
-- This is typically handled in C# code, but adding a note here
-- to remember that a new enum value 'AwaitingDiscountApproval' (10) was added 