namespace EVotingSystem.Models
{
    public class Vote
    {
        public int Id
        {
            get; set;
        }

        public int ElectionId
        {
            get; set;
        }
        public int VoterId
        {
            get; set;
        }

        public string EncryptedData { get; set; } = string.Empty;
        public string EncryptedSessionKey { get; set; } = string.Empty;
        public string DigitalSignature { get; set; } = string.Empty;

        public DateTime Timestamp
        {
            get; set;
        }
    }
}