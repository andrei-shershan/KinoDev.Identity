using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace KinoDev.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [AllowAnonymous]
        [HttpGet("hello")]
        public IActionResult Hello()
        {
            return Ok("hello world of Identity!");
        }
    }
}
