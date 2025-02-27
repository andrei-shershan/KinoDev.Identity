using Newtonsoft.Json;

namespace KinoDev.Identity.Models
{
    public class TokenModel
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }
    }
}
