﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;
using ScanApp;

namespace ScanApp.Migrations
{
    [DbContext(typeof(AppDbContext))]
    partial class AppDbContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "3.1.26");

            modelBuilder.Entity("ScanApp.ScanResult", b =>
                {
                    b.Property<long>("ScanResultId")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("CacheKey")
                        .HasColumnType("TEXT");

                    b.Property<string>("ErrorMessage")
                        .HasColumnType("TEXT");

                    b.Property<string>("FilePath")
                        .HasColumnType("TEXT");

                    b.Property<long>("FileSize")
                        .HasColumnType("INTEGER");

                    b.Property<bool>("IsError")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime?>("LastSeen")
                        .HasColumnType("TEXT");

                    b.Property<string>("MD5")
                        .HasColumnType("TEXT");

                    b.Property<int>("Scanned")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Sha1")
                        .HasColumnType("TEXT");

                    b.Property<string>("Sha256")
                        .HasColumnType("TEXT");

                    b.HasKey("ScanResultId");

                    b.HasIndex("CacheKey");

                    b.HasIndex("MD5");

                    b.HasIndex("Sha1");

                    b.HasIndex("Sha256");

                    b.ToTable("ScanResults");
                });
#pragma warning restore 612, 618
        }
    }
}
