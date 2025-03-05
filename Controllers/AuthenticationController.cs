using KinoDev.Identity.Configurations;
using KinoDev.Identity.Constants;
using KinoDev.Identity.Models;
using KinoDev.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;

namespace KinoDev.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [EnableCors(CorsConstants.AllowedCredentials)]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly AuthenticationSettings _authenticationSettings;

        public AuthenticationController(IAuthenticationService authenticationService, IOptions<AuthenticationSettings> options)
        {
            _authenticationService = authenticationService;
            _authenticationSettings = options.Value;
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> HelloWorld([FromBody] SignInModel userModel)
        {
            var result = await _authenticationService.RegisterAsync(userModel.Email, userModel.Password);
            if (result.IsSuccess)
            {
                return Ok();
            }

            return BadRequest();
        }

        [AllowAnonymous]
        [HttpPost("signin")]
        public async Task<IActionResult> Login([FromBody] SignInModel userModel)
        {
            // TODO: add validation
            var result = await _authenticationService.SignInAsync(userModel.Email, userModel.Password);
            if (result.IsSuccess)
            {
                Response.Cookies.Append(
                    Constants.AuthenticationConstants.RefreshToken,
                    result.Result.RefreshToken,
                    new CookieOptions()
                    {
                        HttpOnly = true,
                        Secure = true,
                        SameSite = SameSiteMode.None,
                        Domain = _authenticationSettings.Domain,
                        Path = "/"
                    });

                Response.Cookies.Append(
                    Constants.AuthenticationConstants.XsrfToken,
                    Guid.NewGuid().ToString(),
                    new CookieOptions()
                    {
                        HttpOnly = false,
                        Secure = true,
                        SameSite = SameSiteMode.None,
                        Domain = _authenticationSettings.Domain,
                        Path = "/"
                    });

                return Ok(new TokenModel()
                {
                    AccessToken = result.Result.AccessToken,
                    ExpiredAt = result.Result.ExpiredAt
                });
            }

            return BadRequest();
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh()
        {
            var csrfTokenFromHeader = Request.Headers[Constants.AuthenticationConstants.XCsrfToken].FirstOrDefault();
            var csrfTokenFromCookie = Request.Cookies[Constants.AuthenticationConstants.XsrfToken];
            var refreshToken = Request.Cookies[Constants.AuthenticationConstants.RefreshToken];

            Console.WriteLine($"{csrfTokenFromHeader}, {csrfTokenFromCookie}, {refreshToken}");

            if (string.IsNullOrWhiteSpace(csrfTokenFromCookie)
                || string.IsNullOrWhiteSpace(csrfTokenFromHeader)
                || csrfTokenFromCookie != csrfTokenFromHeader
                )
            {
                if (!string.IsNullOrWhiteSpace(refreshToken))
                {
                    await _authenticationService.ClearRefreshToken(refreshToken);
                }

                return BadRequest();
            }

            // TODO: add validation
            var result = await _authenticationService.RefreshTokenAsync(refreshToken);
            if (result.IsSuccess)
            {
                return Ok(result.Result);
            }

            return BadRequest();
        }

        [AllowAnonymous]
        [HttpPost("client-token")]
        public IActionResult GetClientToken([FromBody] ClientCredentials request)
        {
            var result = _authenticationService.SignInAsync(request);
            if (result.IsSuccess)
            {
                return Ok(result.Result);
            }

            return BadRequest();
        }
    }
}
