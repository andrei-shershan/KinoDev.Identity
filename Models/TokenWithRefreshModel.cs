using Newtonsoft.Json;

namespace KinoDev.Identity.Models
{
    public class TokenWithRefreshModel : TokenModel
    {
        [JsonProperty(Constants.AuthenticationConstants.RefreshToken)]
        public string RefreshToken { get; set; }
    }
}
