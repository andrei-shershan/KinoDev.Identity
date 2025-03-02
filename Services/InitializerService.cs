using KinoDev.Identity.Constants;
using KinoDev.Shared.Constants;
using Microsoft.AspNetCore.Identity;
using System.Reflection;

namespace KinoDev.Identity.Services
{
    public class InitializerService : IHostedService
    {
        private readonly IServiceProvider _serviceProvider;

        public InitializerService(IServiceProvider serviceProvider)
        {
            _serviceProvider = serviceProvider;
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            using (var scope = _serviceProvider.CreateScope())
            {
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();

                var roles = typeof(Roles)
                    .GetFields(BindingFlags.Public | BindingFlags.Static)
                    .Where(field => field.IsLiteral && !field.IsInitOnly)
                    .Select(field => field.GetRawConstantValue().ToString());

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

                // TODO: Move to env / settings
                // It's for localhost only!
                await CreateUserAndAddToRole(userManager, roleManager, "admin@kinodev.com", Roles.Admin);

                await CreateUserAndAddToRole(userManager, roleManager, "manager@kinodev.com", Roles.Manager);

                await CreateUserAndAddToRole(userManager, roleManager, "cashier@kinodev.com", Roles.Cashier);
            }
        }

        private async Task CreateUserAndAddToRole(
            UserManager<IdentityUser> userManager, 
            RoleManager<IdentityRole> roleManager,
            string email,
            string roleName
        )
        {
            var newUser = new IdentityUser()
            {
                UserName = email,
                Email = email
            };

            // TODO: For local testing all passwords the same, move to env / settings
            await userManager.CreateAsync(newUser, "Test123!");

            await userManager.AddToRoleAsync(newUser, roleName);
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }
}
