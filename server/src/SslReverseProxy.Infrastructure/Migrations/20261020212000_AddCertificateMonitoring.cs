using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddCertificateMonitoring : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Certificates_Domain",
                table: "Certificates");

            migrationBuilder.AddColumn<int>(
                name: "Challenge",
                table: "Certificates",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "CheckedAt",
                table: "Certificates",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LastError",
                table: "Certificates",
                type: "TEXT",
                maxLength: 1000,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "RenewFromSerial",
                table: "Certificates",
                type: "TEXT",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "RenewRequestedAt",
                table: "Certificates",
                type: "TEXT",
                nullable: true);

            // Rows from before this migration were registered by hand.
            migrationBuilder.AddColumn<int>(
                name: "Source",
                table: "Certificates",
                type: "INTEGER",
                nullable: false,
                defaultValue: 1);

            // One row per name, held as Caddy matches it, before the index makes that a rule.
            migrationBuilder.Sql("UPDATE Certificates SET Domain = lower(rtrim(trim(Domain), '.'));");
            migrationBuilder.Sql(
                "DELETE FROM Certificates WHERE rowid NOT IN (SELECT MIN(rowid) FROM Certificates GROUP BY Domain);");
            // A row for a TLS rule's host is that rule's row now.
            migrationBuilder.Sql(
                "UPDATE Certificates SET Source = 0 WHERE Domain IN " +
                "(SELECT lower(rtrim(trim(Domain), '.')) FROM Rules WHERE EnableTls = 1);");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_Domain",
                table: "Certificates",
                column: "Domain",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_Certificates_Domain",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "Challenge",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "CheckedAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "LastError",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "RenewFromSerial",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "RenewRequestedAt",
                table: "Certificates");

            migrationBuilder.DropColumn(
                name: "Source",
                table: "Certificates");

            migrationBuilder.CreateIndex(
                name: "IX_Certificates_Domain",
                table: "Certificates",
                column: "Domain");
        }
    }
}
