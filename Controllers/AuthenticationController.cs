using KinoDev.Identity.Models;
using KinoDev.Identity.Services;
using Microsoft.AspNetCore.Mvc;

namespace KinoDev.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly ISignInService _signInService;

        public AuthenticationController(ISignInService signInService)
        {
            _signInService = signInService;
        }

        // TODO: Remove it as it's for local test only
        //[HttpPost("register")]
        //public async Task<IActionResult> HelloWorld([FromBody] SignInModel userModel)
        //{
        //    var result = await _userManager.CreateAsync(new IdentityUser
        //    {
        //        UserName = userModel.Email,
        //        Email = userModel.Email,
        //    }, userModel.Password);

        //    return Ok("Hello World!");
        //}

        [HttpPost("signin")]
        public async Task<IActionResult> Login([FromBody] SignInModel userModel)
        {
            // TODO: add validation
            var signInResult = await _signInService.SignInAsync(userModel.Email, userModel.Password);
            if (signInResult != null)
            {
                return Ok(signInResult);
            }

            return BadRequest();
        }
    }
}
