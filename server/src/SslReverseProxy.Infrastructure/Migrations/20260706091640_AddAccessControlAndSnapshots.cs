using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddAccessControlAndSnapshots : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AllowedCidrs",
                table: "Rules",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "DeniedCidrs",
                table: "Rules",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.CreateTable(
                name: "ConfigSnapshots",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false),
                    Actor = table.Column<string>(type: "TEXT", maxLength: 200, nullable: false),
                    ConfigJson = table.Column<string>(type: "TEXT", nullable: false),
                    RuleCount = table.Column<int>(type: "INTEGER", nullable: false),
                    Note = table.Column<string>(type: "TEXT", maxLength: 500, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ConfigSnapshots", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ConfigSnapshots_CreatedAt",
                table: "ConfigSnapshots",
                column: "CreatedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ConfigSnapshots");

            migrationBuilder.DropColumn(
                name: "AllowedCidrs",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "DeniedCidrs",
                table: "Rules");
        }
    }
}
