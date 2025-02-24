using KinoDev.Identity.Models;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;

namespace KinoDev.Identity.Services
{
    public interface ISignInService
    {
        Task<SignInResponseModel> SignInAsync(string email, string password);
    }

    public class SignInService : ISignInService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ITokenService _tokenService;

        public SignInService(
            UserManager<IdentityUser> userManager,
            ITokenService tokenService
            )
        {
            _userManager = userManager;
            _tokenService = tokenService;
        }

        public async Task<SignInResponseModel> SignInAsync(string email, string password)
        {
            var user = await _userManager.FindByNameAsync(email);
            if (user == null || string.IsNullOrWhiteSpace(user.Email))
            {
                return null;
            }

            var passwordCheckResult = await _userManager.CheckPasswordAsync(user, password);
            if (!passwordCheckResult)
            {
                return null;
            }

            var token = _tokenService.CreateToken(email);

            return new SignInResponseModel()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                ExpiredAt = token.ValidTo
            };
        }
    }
}