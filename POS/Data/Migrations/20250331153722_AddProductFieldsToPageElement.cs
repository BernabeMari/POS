using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace POS.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddProductFieldsToPageElement : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsProduct",
                table: "PageElements",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<string>(
                name: "ProductDescription",
                table: "PageElements",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "ProductName",
                table: "PageElements",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<decimal>(
                name: "ProductPrice",
                table: "PageElements",
                type: "decimal(18,2)",
                precision: 18,
                scale: 2,
                nullable: false,
                defaultValue: 0m);

            migrationBuilder.AddColumn<int>(
                name: "ProductStockQuantity",
                table: "PageElements",
                type: "int",
                nullable: false,
                defaultValue: 0);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsProduct",
                table: "PageElements");

            migrationBuilder.DropColumn(
                name: "ProductDescription",
                table: "PageElements");

            migrationBuilder.DropColumn(
                name: "ProductName",
                table: "PageElements");

            migrationBuilder.DropColumn(
                name: "ProductPrice",
                table: "PageElements");

            migrationBuilder.DropColumn(
                name: "ProductStockQuantity",
                table: "PageElements");
        }
    }
}
