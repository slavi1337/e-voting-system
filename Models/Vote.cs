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

        public string EncryptedData { get; set; } = string.Empty;
        public string EncryptedSessionKey { get; set; } = string.Empty;

        public string ReceiptHash { get; set; } = string.Empty;

        public string BallotHmac { get; set; } = string.Empty;

        public DateTime Timestamp
        {
            get; set;
        }
    }
}