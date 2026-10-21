using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddRuleSignIn : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "CloudflareAudience",
                table: "Rules",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "CloudflareTeamDomain",
                table: "Rules",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignInProvider",
                table: "Rules",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "SignInVerifierUrl",
                table: "Rules",
                type: "TEXT",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "CloudflareAudience",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "CloudflareTeamDomain",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "SignInProvider",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "SignInVerifierUrl",
                table: "Rules");
        }
    }
}
