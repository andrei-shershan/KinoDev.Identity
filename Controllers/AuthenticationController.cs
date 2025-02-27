using KinoDev.Identity.Models;
using KinoDev.Identity.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KinoDev.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;

        public AuthenticationController(IAuthenticationService authenticationService)
        {
            _authenticationService = authenticationService;
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
                return Ok(result.Result);
            }

            return BadRequest();
        }

        [AllowAnonymous]
        [HttpPost("refresh")]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenModel request)
        {
            // TODO: add validation
            var result = await _authenticationService.RefreshTokenAsync(request.AccessToken, request.RefreshToken);
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
