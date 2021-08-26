using Microsoft.EntityFrameworkCore;
using WebApp.Models;

namespace WebApp.Data
{
    public class WebAppContext : DbContext
    {
        public WebAppContext(DbContextOptions<WebAppContext> options) : base(options)
        {

        }

        public DbSet<Account> Accounts { get; set; }
        public DbSet<Permission> Permissions { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Permission>().ToTable("Permission");
            modelBuilder.Entity<Account>().ToTable("Account");
            modelBuilder.Entity<Vote>().ToTable("Vote");
            modelBuilder.Entity<Answer>().ToTable("Answer");
        }

        public DbSet<WebApp.Models.Vote> Vote { get; set; }
        public DbSet<WebApp.Models.Answer> Answer { get; set; }


    }
}
