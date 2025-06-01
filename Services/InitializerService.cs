using KinoDev.Identity.Configurations;
using KinoDev.Shared.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Reflection;

namespace KinoDev.Identity.Services
{
    public class InitializerService : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        private readonly UserInitialisingSettings _userInitialisingSettings;

        public InitializerService(
            IServiceProvider serviceProvider,
            IOptions<UserInitialisingSettings> options
            )
        {
            _serviceProvider = serviceProvider;
            _userInitialisingSettings = options.Value;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                var roles = typeof(Roles)
                    .GetFields(BindingFlags.Public | BindingFlags.Static)
                    .Where(field => field.IsLiteral && !field.IsInitOnly)
                    .Select(field => field.GetRawConstantValue()?.ToString())
                    .Where(role => !string.IsNullOrWhiteSpace(role));

                foreach (var role in roles)
                {
                    // Check if the role exists
                    if (!await roleManager.RoleExistsAsync(role))
                    {
                        // Create the role if it does not exist
                        await roleManager.CreateAsync(new IdentityRole(role));
                    }
                }

                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

                if (!string.IsNullOrWhiteSpace(_userInitialisingSettings.AdminEmail) &&
                   !string.IsNullOrWhiteSpace(_userInitialisingSettings.AdminPassword))
                {

                    await CreateUserAndAddToRole(
                            userManager,
                            _userInitialisingSettings.AdminEmail,
                            _userInitialisingSettings.AdminPassword,
                            Roles.Admin
                        );
                }

                if (!string.IsNullOrWhiteSpace(_userInitialisingSettings.ManagerEmail) &&
                   !string.IsNullOrWhiteSpace(_userInitialisingSettings.ManagerPassword))
                {

                    await CreateUserAndAddToRole(
                        userManager,
                        _userInitialisingSettings.ManagerEmail,
                        _userInitialisingSettings.ManagerPassword,
                        Roles.Manager
                    );
                }
            }
        }

        private async Task CreateUserAndAddToRole(
            UserManager<IdentityUser> userManager,
            string email,
            string password,
            string roleName
        )
        {
            var user = await userManager.FindByEmailAsync(email);
            if (user != null)
            {
                return;
            }

            var newUser = new IdentityUser()
            {
                UserName = email,
                Email = email
            };

            await userManager.CreateAsync(newUser, password);
            await userManager.AddToRoleAsync(newUser, roleName);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
