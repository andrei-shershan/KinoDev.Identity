using KinoDev.Identity.Configurations;
using KinoDev.Identity.Constants;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace KinoDev.Identity.Services
{
    public interface ITokenService
    {
        JwtSecurityToken GenerateJwtToken(string email, string userId);

        JwtSecurityToken GenerateJwtToken(IdentityUser user, IEnumerable<string> roles);

        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);

        string GenerateRefreshToken();

        JwtSecurityToken GenerateInternalAudienceToken(string clientId);
    }

    public class TokenService : ITokenService
    {
        private readonly AuthenticationSettings _authenticationSettings;

        public TokenService(IOptions<AuthenticationSettings> authenticationSettigns)
        {
            _authenticationSettings = authenticationSettigns.Value;
        }

        public JwtSecurityToken GenerateJwtToken(string email, string userId)
        {
            var authClaims = GetClaims(userId, email);

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authenticationSettings.Secret));

            return new JwtSecurityToken(
               issuer: _authenticationSettings.Issuer,
               audience: _authenticationSettings.Audiences.Gateway,
               expires: DateTime.UtcNow.AddMinutes(_authenticationSettings.Expirations.ShortLivingExpirationInMin),
               claims: authClaims,
               signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }

        public JwtSecurityToken GenerateInternalAudienceToken(string clientId)
        {
            var claims = GetClaims(clientId);

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authenticationSettings.Secret));
            return new JwtSecurityToken(
                issuer: _authenticationSettings.Issuer,
                audience: _authenticationSettings.Audiences.Internal,
                expires: DateTime.UtcNow.AddMinutes(_authenticationSettings.Expirations.ShortLivingExpirationInMin),
                claims: claims,
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );
        }

        public JwtSecurityToken GenerateJwtToken(IdentityUser user, IEnumerable<string> roles)
        {
            var authClaims = GetClaims(user.Id, user.Email);

            authClaims.AddRange(roles.Select(r => new Claim(ClaimTypes.Role, r)));

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authenticationSettings.Secret));
            return new JwtSecurityToken(
                issuer: _authenticationSettings.Issuer,
                audience: _authenticationSettings.Audiences.Gateway,
                expires: DateTime.UtcNow.AddMinutes(_authenticationSettings.Expirations.ShortLivingExpirationInMin),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidateIssuer = true,
                ValidAudience = _authenticationSettings.Audiences.Gateway,
                ValidIssuer = _authenticationSettings.Issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_authenticationSettings.Secret)),
                ValidateLifetime = false // Allow reading expired tokens
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            SecurityToken securityToken;
            return tokenHandler.ValidateToken(token, tokenValidationParameters, out securityToken);
        }

        public string GenerateRefreshToken()
        {
            return Guid.NewGuid().ToString().Replace("-", "");
        }

        private List<Claim> GetClaims(string userId, string email)
        {
            return new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, userId),
                new Claim(ClaimTypes.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };
        }

        private List<Claim> GetClaims(string clientId)
        {
            return new List<Claim>
            {
                new Claim(AuthenticationConstants.ClientId, clientId)
            };
        }
    }
}
