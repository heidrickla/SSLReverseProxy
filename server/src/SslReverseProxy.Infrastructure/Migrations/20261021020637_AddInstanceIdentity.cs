using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SslReverseProxy.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddInstanceIdentity : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "Instance",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false),
                    InstanceId = table.Column<Guid>(type: "TEXT", nullable: false),
                    CreatedAt = table.Column<DateTimeOffset>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_Instance", x => x.Id);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "Instance");
        }
    }
}
