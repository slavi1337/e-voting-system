namespace EVotingSystem.Models
{
    public enum UserRole
    {
        Organizer,
        Voter
    }

    public class User
    {
        public int Id
        {
            get; set;
        }

        public string Username { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;

        public UserRole Role
        {
            get; set;
        }

        public string OrganizationName { get; set; } = string.Empty;
        public string OrgIdNumber { get; set; } = string.Empty;

        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public string JMBG { get; set; } = string.Empty;

        public string CertificateSerialNumber { get; set; } = string.Empty;

        public bool IsRevoked { get; set; } = false;
        public int FailedLoginAttempts { get; set; } = 0;
    }
}