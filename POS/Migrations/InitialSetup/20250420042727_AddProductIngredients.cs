using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace POS.Migrations.InitialSetup
{
    /// <inheritdoc />
    public partial class AddProductIngredients : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<decimal>(
                name: "DiscountAmount",
                table: "Orders",
                type: "decimal(18,2)",
                nullable: false,
                defaultValue: 0m);

            migrationBuilder.AddColumn<string>(
                name: "DiscountApprovedById",
                table: "Orders",
                type: "nvarchar(450)",
                nullable: true);

            migrationBuilder.AddColumn<decimal>(
                name: "DiscountPercentage",
                table: "Orders",
                type: "decimal(18,2)",
                nullable: false,
                defaultValue: 0m);

            migrationBuilder.AddColumn<string>(
                name: "DiscountType",
                table: "Orders",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsDiscountApproved",
                table: "Orders",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsDiscountRequested",
                table: "Orders",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<decimal>(
                name: "OriginalTotalPrice",
                table: "Orders",
                type: "decimal(18,2)",
                nullable: false,
                defaultValue: 0m);

            migrationBuilder.CreateTable(
                name: "ProductIngredients",
                columns: table => new
                {
                    Id = table.Column<int>(type: "int", nullable: false)
                        .Annotation("SqlServer:Identity", "1, 1"),
                    PageElementId = table.Column<int>(type: "int", nullable: false),
                    IngredientName = table.Column<string>(type: "nvarchar(100)", maxLength: 100, nullable: false),
                    Quantity = table.Column<decimal>(type: "decimal(18,2)", precision: 18, scale: 2, nullable: false),
                    Unit = table.Column<string>(type: "nvarchar(20)", maxLength: 20, nullable: false),
                    Notes = table.Column<string>(type: "nvarchar(255)", maxLength: 255, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProductIngredients", x => x.Id);
                    table.ForeignKey(
                        name: "FK_ProductIngredients_PageElements_PageElementId",
                        column: x => x.PageElementId,
                        principalTable: "PageElements",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_Orders_DiscountApprovedById",
                table: "Orders",
                column: "DiscountApprovedById");

            migrationBuilder.CreateIndex(
                name: "IX_ProductIngredients_PageElementId",
                table: "ProductIngredients",
                column: "PageElementId");

            migrationBuilder.AddForeignKey(
                name: "FK_Orders_AspNetUsers_DiscountApprovedById",
                table: "Orders",
                column: "DiscountApprovedById",
                principalTable: "AspNetUsers",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_Orders_AspNetUsers_DiscountApprovedById",
                table: "Orders");

            migrationBuilder.DropTable(
                name: "ProductIngredients");

            migrationBuilder.DropIndex(
                name: "IX_Orders_DiscountApprovedById",
                table: "Orders");

            migrationBuilder.DropColumn(
                name: "DiscountAmount",
                table: "Orders");

            migrationBuilder.DropColumn(
                name: "DiscountApprovedById",
                table: "Orders");

            migrationBuilder.DropColumn(
                name: "DiscountPercentage",
                table: "Orders");

            migrationBuilder.DropColumn(
                name: "DiscountType",
                table: "Orders");

            migrationBuilder.DropColumn(
                name: "IsDiscountApproved",
                table: "Orders");

            migrationBuilder.DropColumn(
                name: "IsDiscountRequested",
                table: "Orders");

            migrationBuilder.DropColumn(
                name: "OriginalTotalPrice",
                table: "Orders");
        }
    }
}
