using Newtonsoft.Json;

namespace KinoDev.Identity.Models
{
    public class SignInResponseModel
    {
        [JsonProperty("access_token")]
        public string Token { get; set; }

        [JsonProperty("expired_at")]
        public DateTime ExpiredAt { get; set; }
    }
}
