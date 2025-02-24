using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace KinoDev.Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet("hello")]
        public IActionResult Hello()
        {
            return Ok("hello world of Identity!");
        }
    }
}
