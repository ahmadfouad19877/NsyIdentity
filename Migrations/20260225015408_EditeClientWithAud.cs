using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityServerNSY.Migrations
{
    /// <inheritdoc />
    public partial class EditeClientWithAud : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AllowedAudiences",
                table: "AllowedClients");

            migrationBuilder.RenameColumn(
                name: "IsEnabled",
                table: "AllowedClients",
                newName: "IsActive");

            migrationBuilder.RenameColumn(
                name: "CreatedAt",
                table: "AllowedClients",
                newName: "CreatedAtUtc");

            migrationBuilder.AddColumn<DateTime>(
                name: "DeactivatedAtUtc",
                table: "AllowedClients",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "ExpiresAtUtc",
                table: "AllowedClients",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Note",
                table: "AllowedClients",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.CreateTable(
                name: "AllowedAudiences",
                columns: table => new
                {
                    Id = table.Column<Guid>(type: "uniqueidentifier", nullable: false),
                    ClientId = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    Audience = table.Column<string>(type: "nvarchar(max)", nullable: false),
                    IsActive = table.Column<bool>(type: "bit", nullable: false),
                    CreatedAtUtc = table.Column<DateTime>(type: "datetime2", nullable: false),
                    Note = table.Column<string>(type: "nvarchar(max)", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_AllowedAudiences", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "AllowedAudiences");

            migrationBuilder.DropColumn(
                name: "DeactivatedAtUtc",
                table: "AllowedClients");

            migrationBuilder.DropColumn(
                name: "ExpiresAtUtc",
                table: "AllowedClients");

            migrationBuilder.DropColumn(
                name: "Note",
                table: "AllowedClients");

            migrationBuilder.RenameColumn(
                name: "IsActive",
                table: "AllowedClients",
                newName: "IsEnabled");

            migrationBuilder.RenameColumn(
                name: "CreatedAtUtc",
                table: "AllowedClients",
                newName: "CreatedAt");

            migrationBuilder.AddColumn<string>(
                name: "AllowedAudiences",
                table: "AllowedClients",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }
    }
}
