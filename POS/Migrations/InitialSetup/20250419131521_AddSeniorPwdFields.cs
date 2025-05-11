using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace POS.Migrations.InitialSetup
{
    /// <inheritdoc />
    public partial class AddSeniorPwdFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<bool>(
                name: "IsPWD",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<bool>(
                name: "IsSeniorCitizen",
                table: "AspNetUsers",
                type: "bit",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "IsPWD",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "IsSeniorCitizen",
                table: "AspNetUsers");
        }
    }
}
