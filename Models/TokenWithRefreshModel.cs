using Newtonsoft.Json;

namespace KinoDev.Identity.Models
{
    public class TokenWithRefreshModel : TokenModel
    {
        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }
}
