using Newtonsoft.Json;

namespace KinoDev.Identity.Models
{
    public class TokenWithRefreshModel : TokenModel
    {
        [JsonProperty("expired_at")]
        public DateTime ExpiredAt { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }
}
