namespace EVotingSystem.Models
{
    public class VotingParticipation
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
        public DateTime Timestamp
        {
            get; set;
        }
    }
}