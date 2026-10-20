using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddTrafficSamples : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "TrafficSamples",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    At = table.Column<long>(type: "INTEGER", nullable: false),
                    Requests = table.Column<long>(type: "INTEGER", nullable: false),
                    Status2xx = table.Column<long>(type: "INTEGER", nullable: false),
                    Status3xx = table.Column<long>(type: "INTEGER", nullable: false),
                    Status4xx = table.Column<long>(type: "INTEGER", nullable: false),
                    Status5xx = table.Column<long>(type: "INTEGER", nullable: false),
                    BytesIn = table.Column<long>(type: "INTEGER", nullable: false),
                    BytesOut = table.Column<long>(type: "INTEGER", nullable: false),
                    DurationSumSeconds = table.Column<double>(type: "REAL", nullable: false),
                    TtfbSumSeconds = table.Column<double>(type: "REAL", nullable: false),
                    TtfbCount = table.Column<long>(type: "INTEGER", nullable: false),
                    DurationBuckets = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
                    InFlight = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_TrafficSamples", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_TrafficSamples_At",
                table: "TrafficSamples",
                column: "At");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "TrafficSamples");
        }
    }
}
