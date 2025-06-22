namespace KinoDev.Identity.Configurations
{
    public class InMemoryDbSettings
    {
        public bool Enabled { get; set; } = false;
        public string DatabaseName { get; set; } = string.Empty;
    }
}