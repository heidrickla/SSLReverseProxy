using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddProxyHardeningOptions : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "AdditionalUpstreams",
                table: "Rules",
                type: "TEXT",
                maxLength: 4096,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "DialTimeoutSeconds",
                table: "Rules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "EnableSecurityHeaders",
                table: "Rules",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            // Any rule that already exists opts in too. Done with UPDATE rather
            // than a column default: EF treats a bool's CLR default as "unset",
            // so a store default of true would make EnableSecurityHeaders=false
            // unsavable. The two headers this turns on (X-Content-Type-Options,
            // Referrer-Policy) cannot break a working site; the ones that could
            // - HSTS and X-Frame-Options - stay opt-in and are not touched here.
            migrationBuilder.Sql("UPDATE Rules SET EnableSecurityHeaders = 1;");

            migrationBuilder.AddColumn<string>(
                name: "FrameOptions",
                table: "Rules",
                type: "TEXT",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HealthCheckExpectStatus",
                table: "Rules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HealthCheckIntervalSeconds",
                table: "Rules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "HealthCheckPath",
                table: "Rules",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "HealthCheckTimeoutSeconds",
                table: "Rules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "HstsIncludeSubdomains",
                table: "Rules",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "HstsMaxAgeDays",
                table: "Rules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "LoadBalancePolicy",
                table: "Rules",
                type: "TEXT",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "MaxRequestBodyBytes",
                table: "Rules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "SkipAccessLog",
                table: "Rules",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.AddColumn<int>(
                name: "UpstreamReadTimeoutSeconds",
                table: "Rules",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "UpstreamWriteTimeoutSeconds",
                table: "Rules",
                type: "INTEGER",
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "AdditionalUpstreams",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "DialTimeoutSeconds",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "EnableSecurityHeaders",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "FrameOptions",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "HealthCheckExpectStatus",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "HealthCheckIntervalSeconds",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "HealthCheckPath",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "HealthCheckTimeoutSeconds",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "HstsIncludeSubdomains",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "HstsMaxAgeDays",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "LoadBalancePolicy",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "MaxRequestBodyBytes",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "SkipAccessLog",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "UpstreamReadTimeoutSeconds",
                table: "Rules");

            migrationBuilder.DropColumn(
                name: "UpstreamWriteTimeoutSeconds",
                table: "Rules");
        }
    }
}
