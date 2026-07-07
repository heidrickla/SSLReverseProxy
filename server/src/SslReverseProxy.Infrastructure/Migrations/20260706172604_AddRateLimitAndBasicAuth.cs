using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddRateLimitAndBasicAuth : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BasicAuthPasswordHash",
                table: "Rules",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BasicAuthUsername",
                table: "Rules",
                type: "TEXT",
                maxLength: 200,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "RateLimitPerMinute",
                table: "Rules",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BasicAuthPasswordHash",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "BasicAuthUsername",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "RateLimitPerMinute",
                table: "Rules");
        }
    }
}
