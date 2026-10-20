using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateAlerts : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "AlertedExpiresAt",
                table: "Certificates",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "AlertedStatus",
                table: "Certificates",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AlertedExpiresAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "AlertedStatus",
                table: "Certificates");
        }
    }
}
