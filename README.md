[Paddle billing](https://www.paddle.com/billing) is the new product from _Paddle_. Since they did not have any SDK for dotnet I made this repo, while it is not in nuget and is not published as SDK you could find some usefull files and tools to copy paste. 
## Checking webhook signatures
Decorate your webhook controllers with `EnsureIsFromPaddleAttribute`. You should have the `Paddle secret Key` bound to the `IOptions<AppSettings>`.
```Csharp
namespace yourApp.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PaddleWebHookController(
                                         ILogger<PaddleWebHookController> logger,
                                         IOptions<AppSettings> options) : ControllerBase
    {
        readonly AppSettings appSettings = options.Value;

        [HttpPost, EnsureIsFromPaddleBilling, Route("[action]")]
        public async Task<ActionResult> RegisterEvent([FromBody] string eventModel)
        {
            //if we are here we can trust the content of the request
            
        }
    }
}
```
