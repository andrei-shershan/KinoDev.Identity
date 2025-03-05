using KinoDev.Identity.Configurations;
using KinoDev.Identity.Constants;
using KinoDev.Identity.DbContexts;
using KinoDev.Identity.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System.Text;

namespace KinoDev.Identity
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            // Add services to the container.
            builder.Configuration
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                //.AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();

            builder.Services.AddControllers()
                .AddNewtonsoftJson();

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            builder.Services.Configure<AuthenticationSettings>(builder.Configuration.GetSection("Authentication"));

            var authenticationSettings = builder.Configuration.GetSection("Authentication").Get<AuthenticationSettings>();
            if (authenticationSettings is null)
            {
                throw new InvalidConfigurationException("Cannot obtain AuthenticationSettings from configuration");
            }

            var connectionString = builder.Configuration.GetConnectionString("Identity");
            if (string.IsNullOrWhiteSpace(connectionString))
            {
                throw new InvalidConfigurationException("Cannot obtain ConnectionString from configuration");
            }

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseMySql(
                    connectionString,
                    ServerVersion.AutoDetect(connectionString)
                )
                // TODO: Allow it for local development only
                .EnableSensitiveDataLogging()
                .LogTo(Console.WriteLine, LogLevel.Information);
            });

            // Identity
            builder.Services.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = AuthenticationConstants.JwtBearer;
                options.DefaultChallengeScheme = AuthenticationConstants.JwtBearer;
            })
            .AddJwtBearer(AuthenticationConstants.JwtBearer, options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = authenticationSettings.Issuer,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(authenticationSettings.Secret)),
                    ClockSkew = TimeSpan.Zero
                };
            });

            builder.Services.AddScoped<ITokenService, TokenService>();
            builder.Services.AddTransient<IAuthenticationService, AuthenticationService>();

            // TODO: It's for local dev only
            builder.Services.Configure<IdentityOptions>(options =>
            {
                // Password settings.
                options.Password.RequiredLength = 6;
                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequiredUniqueChars = 1;
            });

            builder.Services.AddCors(options =>
            {
                if (!string.IsNullOrWhiteSpace(authenticationSettings.CORS.AllowedCredentialsOrigins))
                {
                    options.AddPolicy(CorsConstants.AllowedCredentials, policy =>
                    {
                        policy
                            .WithOrigins(authenticationSettings.CORS.AllowedCredentialsOrigins.Split(","))
                            .AllowAnyHeader()
                            .AllowAnyMethod()
                            .AllowCredentials();
                    });
                }
            });

            builder.Services.AddHostedService<InitializerService>();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            // TODO: Disable for localhost only
            // app.UseHttpsRedirection();

            app.UseCors();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
