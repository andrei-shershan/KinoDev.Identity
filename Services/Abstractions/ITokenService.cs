using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace KinoDev.Identity.Services.Abstractions
{
    public interface ITokenService
    {
        JwtSecurityToken GenerateJwtToken(string email, string userId, IEnumerable<string>? roles = null);

        JwtSecurityToken GenerateJwtToken(IdentityUser user, IEnumerable<string> roles);

        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);

        string GenerateRefreshToken();

        JwtSecurityToken GenerateInternalAudienceToken(string clientId);
    }
}