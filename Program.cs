
using Microsoft.EntityFrameworkCore;
using WebApplication1.Repositories;
using WebApplication1.Services;
using WebApplication1.Utilities;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using WebApplication1.Configuration;
using WebApplication1.Interface;

namespace WebApplication1
{
    public class Program
    {
        public static void Main(string[] args)
        {

            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container
            builder.Services.AddControllers();
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            // Database connection
            builder.Services.AddDbContext<AppDbContext>(options =>
                options.UseSqlServer("Server=(localdb)\\mssqllocaldb;Database=GameServerDB;Trusted_Connection=True;"));

            builder.Services.AddMemoryCache();

            // Dependency injection
            builder.Services.AddScoped<AuthService>();
            builder.Services.AddSingleton<JwtService>();
            builder.Services.AddScoped<UserRepository>();
            builder.Services.AddSingleton<PasswordHasher>();

            builder.Services.AddSingleton<ITokenRepository, TokenRepository>();
            builder.Services.AddMemoryCache();

            builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));
            //builder.Services.AddSingleton<JwtService>();

            //builder.Services.AddScoped<JwtService>();
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Secret"]))
                    };
                });
            builder.Services.AddAuthorization();


            var app = builder.Build();

            // Configure middleware
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();
            app.UseAuthorization();
            app.MapControllers();
            app.Run();

        }
    }
}
