using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebApplication1.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductController : ControllerBase
    {
        // Testing ground. Simple Get and Post.
        [HttpGet("{id}")]
        public IActionResult Read(int id)
        {
            return Ok(new { id, Name = "My Name" });
        }
        [HttpPost]
        public IActionResult Create(WeatherForecast weatherForecast)
        {
            return Created(string.Empty, weatherForecast);
        }
    }
}
