using KinoDev.Identity.Models;
using KinoDev.Identity.ServiceErrors;
using KinoDev.Shared.InfrastructureModels;

namespace KinoDev.Identity.Services.Abstractions
{
    public interface IAuthenticationService
    {
        Task<OperationResult<bool, AuthenticationServiceError>> RegisterAsync(string email, string password);

        Task<OperationResult<TokenWithRefreshModel, AuthenticationServiceError>> SignInAsync(string email, string password);

        OperationResult<TokenModel, AuthenticationServiceError> SignInAsync(ClientCredentials clientCredentialsRequest);

        Task<OperationResult<TokenModel, AuthenticationServiceError>> RefreshTokenAsync(string refreshToken);

        Task ClearRefreshToken(string refreshToken);
    }
}