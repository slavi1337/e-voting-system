namespace EVotingSystem.Models
{
    public class Election
    {
        public int Id
        {
            get; set;
        }
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;

        public DateTime StartDate
        {
            get; set;
        }
        public DateTime EndDate
        {
            get; set;
        }

        public bool IsActive => DateTime.Now >= StartDate && DateTime.Now <= EndDate;
        public bool IsFinished => DateTime.Now > EndDate;

        public List<Candidate> Candidates { get; set; } = new List<Candidate>();

        public int OrganizerId
        {
            get; set;
        }
    }

    public class Candidate
    {
        public int Id
        {
            get; set;
        }
        public string Name { get; set; } = string.Empty;
        public int VoteCount { get; set; } = 0;
        public bool IsSelected { get; set; } = false;
    }
}