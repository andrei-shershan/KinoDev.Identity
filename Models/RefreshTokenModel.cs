using Newtonsoft.Json;

namespace KinoDev.Identity.Models
{
    public class RefreshTokenModel
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }
}
