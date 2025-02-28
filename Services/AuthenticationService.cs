using KinoDev.Identity.Configurations;
using KinoDev.Identity.DbContexts;
using KinoDev.Identity.DbModels;
using KinoDev.Identity.Models;
using KinoDev.Identity.ServiceErrors;
using KinoDev.Shared.InfrastructureModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace KinoDev.Identity.Services
{
    public interface IAuthenticationService
    {
        Task<OperationResult<bool, AuthenticationServiceError>> RegisterAsync(string email, string password);

        Task<OperationResult<TokenWithRefreshModel, AuthenticationServiceError>> SignInAsync(string email, string password);

        OperationResult<TokenModel, AuthenticationServiceError> SignInAsync(ClientCredentials clientCredentialsRequest);

        Task<OperationResult<TokenWithRefreshModel, AuthenticationServiceError>> RefreshTokenAsync(string accessToken, string refreshToken);
    }

    public class AuthenticationService : IAuthenticationService
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly ITokenService _tokenService;
        private readonly AuthenticationSettings _authenticationSettings;

        public AuthenticationService(
            UserManager<IdentityUser> userManager,
            ApplicationDbContext applicationDbContext,
            ITokenService tokenService,
            IOptions<AuthenticationSettings> options
            )
        {
            _applicationDbContext = applicationDbContext;
            _userManager = userManager;
            _tokenService = tokenService;
            _authenticationSettings = options.Value;
        }

        public async Task<OperationResult<TokenWithRefreshModel, AuthenticationServiceError>> RefreshTokenAsync(string accessToken, string refreshToken)
        {
            try
            {
                var principal = _tokenService.GetPrincipalFromExpiredToken(accessToken);
                if (principal == null)
                {
                    return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InvalidData);
                }

                var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);

                var storedRefreshToken = _applicationDbContext.RefreshTokens.FirstOrDefault(x => x.Token == refreshToken && x.UserId == userId);
                if (storedRefreshToken == null)
                {
                    return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InvalidData);
                }

                if (storedRefreshToken.IsExpired)
                {
                    _applicationDbContext.RefreshTokens.Remove(storedRefreshToken);
                    await _applicationDbContext.SaveChangesAsync();
                    return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InvalidData);
                }

                var user = await _userManager.FindByIdAsync(userId);
                var roles = await _userManager.GetRolesAsync(user);
                var newAccessToken = _tokenService.GenerateJwtToken(user, roles);

                return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Success(new TokenWithRefreshModel()
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(newAccessToken),
                    RefreshToken = storedRefreshToken.Token,
                    ExpiredAt = newAccessToken.ValidTo
                });
            }
            catch (Exception ex)
            {
                return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InternalError, ex.Message);
            }
        }

        public async Task<OperationResult<bool, AuthenticationServiceError>> RegisterAsync(string email, string password)
        {
            try
            {
                // TODO: Add valdiations
                if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
                {
                    return OperationResult<bool, AuthenticationServiceError>.Failure(AuthenticationServiceError.InvalidData);
                }

                var user = await _userManager.CreateAsync(new IdentityUser
                {
                    UserName = email,
                    Email = email,
                }, password);

                if (user == null)
                {
                    return OperationResult<bool, AuthenticationServiceError>.Failure(AuthenticationServiceError.InternalError);
                }

                return OperationResult<bool, AuthenticationServiceError>.Success(true);
            }
            catch (Exception ex)
            {
                return OperationResult<bool, AuthenticationServiceError>.Failure(AuthenticationServiceError.InternalError, ex.Message);
            }
        }

        public async Task<OperationResult<TokenWithRefreshModel, AuthenticationServiceError>> SignInAsync(string email, string password)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null || string.IsNullOrWhiteSpace(user.Email))
                {
                    return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InvalidData);
                }

                var passwordCheckResult = await _userManager.CheckPasswordAsync(user, password);
                if (!passwordCheckResult)
                {
                    return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InvalidData);
                }

                var accessToken = _tokenService.GenerateJwtToken(email, user.Id);
                var refreshToken = _tokenService.GenerateRefreshToken();

                await _applicationDbContext.RefreshTokens.AddAsync(new DbModels.RefreshToken()
                {
                    Token = refreshToken,
                    UserId = user.Id,
                    Expires = DateTime.UtcNow.AddMinutes(_authenticationSettings.Expirations.LongLivingExpirationInMin),
                    Created = DateTime.Now
                });

                await _applicationDbContext.SaveChangesAsync();

                return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Success(new TokenWithRefreshModel()
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
                    RefreshToken = refreshToken,
                    ExpiredAt = accessToken.ValidTo
                });
            }
            catch (Exception ex)
            {
                return OperationResult<TokenWithRefreshModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InternalError, ex.Message);
            }
        }

        public OperationResult<TokenModel, AuthenticationServiceError> SignInAsync(ClientCredentials clientCredentialsRequest)
        {
            try
            {
                if (clientCredentialsRequest.ClientId != _authenticationSettings.ClientId
                    || clientCredentialsRequest.ClientSecret != _authenticationSettings.ClientSecret
                )
                {
                    return OperationResult<TokenModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InvalidData);
                }

                var token = _tokenService.GenerateInternalAudienceToken(clientCredentialsRequest.ClientId);
                if (token == null)
                {
                    return OperationResult<TokenModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InternalError);
                }

                return OperationResult<TokenModel, AuthenticationServiceError>.Success(new TokenModel()
                {
                    AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
                    ExpiredAt = token.ValidTo
                });
            }
            catch (Exception ex)
            {
                return OperationResult<TokenModel, AuthenticationServiceError>.Failure(AuthenticationServiceError.InternalError, ex.Message);
            }
        }
    }
}
