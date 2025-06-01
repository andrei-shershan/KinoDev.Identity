using KinoDev.Identity.Configurations;
using KinoDev.Identity.Constants;
using KinoDev.Identity.DbContexts;
using KinoDev.Identity.Services;
using KinoDev.Identity.Services.Abstractions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Protocols.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace KinoDev.Identity
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            builder.Configuration
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables();

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

            builder.Services.Configure<AuthenticationSettings>(builder.Configuration.GetSection("Authentication"));
            builder.Services.Configure<UserInitialisingSettings>(builder.Configuration.GetSection("UserInitialising"));

            builder.Services.AddControllers()
                .AddNewtonsoftJson();

            builder.Services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseMySql(
                    connectionString,
                    ServerVersion.AutoDetect(connectionString)
                );
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

            builder.Services.AddHealthChecks();

            var app = builder.Build();

            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            var disableHttpsRedirection = builder.Configuration.GetValue<bool>("DisableHttpsRedirection");
            if (!disableHttpsRedirection)
            {
                app.UseHttpsRedirection();
            }

            app.UseCors();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}
