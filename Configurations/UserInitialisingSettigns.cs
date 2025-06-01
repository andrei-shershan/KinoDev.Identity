namespace KinoDev.Identity.Configurations
{
    public class UserInitialisingSettings
    {
        public required string AdminEmail { get; set; }

        public required string AdminPassword { get; set; }

        public required string ManagerEmail { get; set; }
        
        public required string ManagerPassword { get; set; }
    }
}