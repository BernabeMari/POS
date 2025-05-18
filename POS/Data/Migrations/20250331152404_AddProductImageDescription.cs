using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace POS.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddProductImageDescription : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "ImageDescription",
                table: "Products",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: false,
                defaultValue: "");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "ImageDescription",
                table: "Products");
        }
    }
}
