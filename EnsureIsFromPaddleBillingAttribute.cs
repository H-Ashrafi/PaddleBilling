using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace PaddleBilling.Filters
{
    /// <summary>
    /// checks the signature in the paddle billing web-hooks
    /// </summary>
    public class EnsureIsFromPaddleBillingAttribute() : TypeFilterAttribute(typeof(EnsureIsFromPaddleBillingFilter))
    {
        /// <summary>
        /// checks the signature in the paddle billing web-hooks
        /// </summary>
        /// <param name="options"></param>
        /// <param name="logger"></param>
        public class EnsureIsFromPaddleBillingFilter(IOptions<AppSettings> options,
                                                     ILogger<EnsureIsFromPaddleBillingFilter> logger) : IAsyncResourceFilter
        {
            readonly AppSettings _settings = options.Value;

            public async Task OnResourceExecutionAsync(ResourceExecutingContext context, ResourceExecutionDelegate next)
            {
                logger.LogInformation("Assessing paddle billing signature ...");

                //what comes form paddle looks like this 
                //ts=1671552777;h1=eb4d0dc8853be92b7f063b9f3ba5233eb920a09459b6e6b2c26705b4364db151
                var sigHeaderContent = context.HttpContext.Request.Headers["Paddle-Signature"].FirstOrDefault();
                if (string.IsNullOrEmpty(sigHeaderContent))
                {
                    logger.LogWarning("signature content was empty");
                    context.Result = new UnauthorizedResult();
                    return;
                }
                logger.LogInformation("Paddle-Signature is {sig}", sigHeaderContent);


                var parts = sigHeaderContent?.Split(';');
                if (parts is null)
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                var tsValue = parts?.First().Split('=').Last();

                //they might add secret rotation in future
                var h1Value = parts?.Last().Split('=').Last();

                //check for empty values
                if (string.IsNullOrEmpty(tsValue) || string.IsNullOrEmpty(h1Value))
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                //try converting the string into long
                if (!long.TryParse(tsValue, out long ts))
                {
                    context.Result = new UnauthorizedResult();
                    return;
                }

                var timeOfEvent = DateTimeOffset.FromUnixTimeSeconds(ts);
                var fiveMinAgo = DateTime.UtcNow.Subtract(new TimeSpan(0, 5, 0));

                //time of event should not be in the future nor should it be too old
                if (timeOfEvent > DateTimeOffset.UtcNow || timeOfEvent < fiveMinAgo)
                {
                    logger.LogWarning("the event was fired {@TimeOfEvent} which would not match {@currentTime} {@traceId}", timeOfEvent, DateTime.UtcNow, context.HttpContext.TraceIdentifier);
                    context.Result = new UnauthorizedResult();
                    return;
                }
                var hashBytes = new byte[HMACSHA256.HashSizeInBytes];
                context.HttpContext.Request.EnableBuffering();

                // Leave the body open so the next middleware can read it.
                using (var reader = new StreamReader(
                    context.HttpContext.Request.Body,
                    encoding: Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    leaveOpen: true))
                {
                    var bodyContent = await reader.ReadToEndAsync();

                    //hash it like paddle does
                    var data = new StringBuilder().AppendFormat("{0}:{1}", tsValue, bodyContent).ToString();

                    hashBytes = HMACSHA256.HashData(key: GetBytesOf(_settings.PaddleEventSecret), source: GetBytesOf(data));
                    // Reset the request body stream position so the next middleware can read it
                    context.HttpContext.Request.Body.Position = 0;
                }
                // Convert the hash byte array to a hex string.
                StringBuilder computedHexHash = new(hashBytes.Length * 2);
                foreach (byte b in hashBytes)
                {
                    computedHexHash.AppendFormat("{0:x2}", b);
                }
                //compare the hashes
                //if they do not match it's not from them.
                if (!computedHexHash.Equals(h1Value.AsSpan()))
                {
                    logger.LogWarning("hashes do not match {@paddleHashValue} != {@computedHash}", h1Value, computedHexHash);
                    context.Result = new UnauthorizedResult();
                    return;
                }
                //if did not change the response result pass onto next handlers
                if (context.Result is null)
                {
                    await next();
                }
            }

            private byte[] GetBytesOf(string data)=>
                Encoding.UTF8.GetBytes(data);
            
        }
    }
}
