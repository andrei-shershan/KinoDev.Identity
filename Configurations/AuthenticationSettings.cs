namespace KinoDev.Identity.Configurations
{
    public class AuthenticationSettings
    {
        public string Secret { get; set; }

        public string Issuer { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public Expiration Expirations { get; set; }

        public Audience Audiences { get; set; }
    }

    public class Audience
    {
        public string Internal { get; set; }

        public string Gateway { get; set; }
    }

    public class Expiration
    {
        public int ShortLivingExpirationInMin { get; set; }

        public int LongLivingExpirationInMin { get; set; }
    }
}
