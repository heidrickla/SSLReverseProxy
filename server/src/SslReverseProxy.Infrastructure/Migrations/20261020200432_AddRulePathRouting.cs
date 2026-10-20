using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddRulePathRouting : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "PathPrefix",
                table: "Rules",
                type: "TEXT",
                maxLength: 256,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "StripPathPrefix",
                table: "Rules",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "PathPrefix",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "StripPathPrefix",
                table: "Rules");
        }
    }
}
