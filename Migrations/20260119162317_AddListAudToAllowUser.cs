using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityServerNSY.Migrations
{
    /// <inheritdoc />
    public partial class AddListAudToAllowUser : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AllowedAudiences",
                table: "AllowedClients",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "[]");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowedAudiences",
                table: "AllowedClients");
        }
    }
}
