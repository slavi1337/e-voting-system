using Org.BouncyCastle.Crypto;

namespace EVotingSystem.Models
{
    public static class AppSession
    {
        public static User? CurrentUser
        {
            get; set;
        }

        public static AsymmetricKeyParameter? CurrentUserPrivateKey
        {
            get; set;
        }
    }
}