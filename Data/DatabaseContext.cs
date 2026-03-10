using EVotingSystem.Models;
using EVotingSystem.Services.Cryptography;
using Newtonsoft.Json;
using System.Data.SQLite;
using System.IO;

namespace EVotingSystem.Data
{
    public class DatabaseContext
    {
        private const string DbName = "evoting_db.sqlite";
        private readonly string _connectionString;

        public DatabaseContext()
        {
            _connectionString = $"Data Source={DbName};Version=3;";
            InitializeDatabase();
        }

        private void InitializeDatabase()
        {
            if (!File.Exists(DbName))
            {
                SQLiteConnection.CreateFile(DbName);

                using (var conn = new SQLiteConnection(_connectionString))
                {
                    conn.Open();

                    string sql = @"
                        CREATE TABLE Users (
                            Id INTEGER PRIMARY KEY AUTOINCREMENT,
                            Username TEXT UNIQUE,
                            PasswordHash TEXT,
                            Role TEXT,
                            CertificateSerialNumber TEXT,
                            IsRevoked INTEGER,
                            FailedLoginAttempts INTEGER,
                            OrganizationName TEXT,
                            OrgIdNumber TEXT,
                            FirstName TEXT,
                            LastName TEXT,
                            JMBG TEXT
                        );

                        CREATE TABLE Elections (
                            Id INTEGER PRIMARY KEY AUTOINCREMENT,
                            Title TEXT,
                            Description TEXT,
                            StartDate TEXT,
                            EndDate TEXT,
                            OrganizerId INTEGER,
                            CandidatesJson TEXT,
                            Hmac TEXT
                        );

                        CREATE TABLE Votes (
                            Id INTEGER PRIMARY KEY AUTOINCREMENT,
                            ElectionId INTEGER,
                            VoterId INTEGER,
                            EncryptedData TEXT,
                            EncryptedSessionKey TEXT,
                            DigitalSignature TEXT,
                            Timestamp TEXT,
                            UNIQUE(ElectionId, VoterId)
                        );
                    ";

                    using (var command = new SQLiteCommand(sql, conn))
                    {
                        command.ExecuteNonQuery();
                    }
                }
            }
        }

        public SQLiteConnection GetConnection()
        {
            return new SQLiteConnection(_connectionString);
        }

        public bool UserExists(string username)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "SELECT COUNT(*) FROM Users WHERE Username = @u";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@u", username);
                    long count = (long)cmd.ExecuteScalar();
                    return count > 0;
                }
            }
        }

        public void AddUser(User user)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = @"
                    INSERT INTO Users (Username, PasswordHash, Role, CertificateSerialNumber, 
                                       OrganizationName, OrgIdNumber, FirstName, LastName, JMBG)
                    VALUES (@uname, @pass, @role, @certSerial, @orgName, @orgId, @fname, @lname, @jmbg)";

                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@uname", user.Username);
                    cmd.Parameters.AddWithValue("@pass", user.PasswordHash);
                    cmd.Parameters.AddWithValue("@role", user.Role.ToString());
                    cmd.Parameters.AddWithValue("@certSerial", user.CertificateSerialNumber);

                    cmd.Parameters.AddWithValue("@orgName", user.OrganizationName ?? "");
                    cmd.Parameters.AddWithValue("@orgId", user.OrgIdNumber ?? "");
                    cmd.Parameters.AddWithValue("@fname", user.FirstName ?? "");
                    cmd.Parameters.AddWithValue("@lname", user.LastName ?? "");
                    cmd.Parameters.AddWithValue("@jmbg", user.JMBG ?? "");

                    cmd.ExecuteNonQuery();
                }
            }
        }

        public User GetUserByUsername(string username)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "SELECT * FROM Users WHERE Username = @u";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@u", username);
                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return new User
                            {
                                Id = reader.IsDBNull(reader.GetOrdinal("Id")) ? 0 : Convert.ToInt32(reader["Id"]),
                                Username = reader["Username"].ToString() ?? "",
                                PasswordHash = reader["PasswordHash"].ToString() ?? "",
                                Role = Enum.Parse<UserRole>(reader["Role"].ToString() ?? "Voter"),
                                CertificateSerialNumber = reader["CertificateSerialNumber"].ToString() ?? "",
                                IsRevoked = reader.IsDBNull(reader.GetOrdinal("IsRevoked")) ? false : Convert.ToBoolean(reader["IsRevoked"]),
                                FailedLoginAttempts = reader.IsDBNull(reader.GetOrdinal("FailedLoginAttempts")) ? 0 : Convert.ToInt32(reader["FailedLoginAttempts"]),
                                FirstName = reader["FirstName"].ToString() ?? "",
                                LastName = reader["LastName"].ToString() ?? "",
                                OrganizationName = reader["OrganizationName"].ToString() ?? "",
                                OrgIdNumber = reader["OrgIdNumber"].ToString() ?? "",
                                JMBG = reader["JMBG"].ToString() ?? ""
                            };
                        }
                    }
                }
            }
            return null;
        }
        public void UpdateUser(User user)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "UPDATE Users SET FailedLoginAttempts = @fails, IsRevoked = @revoked WHERE Id = @id";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@fails", user.FailedLoginAttempts);
                    cmd.Parameters.AddWithValue("@revoked", user.IsRevoked ? 1 : 0);
                    cmd.Parameters.AddWithValue("@id", user.Id);
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public void AddElection(Election election)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = @"
                    INSERT INTO Elections (Title, Description, StartDate, EndDate, OrganizerId, CandidatesJson, Hmac)
                    VALUES (@title, @desc, @start, @end, @orgId, @candidates, @hmac)";

                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    string candidatesJson = JsonConvert.SerializeObject(election.Candidates);
                    string startDateStr = election.StartDate.ToString("o");
                    string endDateStr = election.EndDate.ToString("o");

                    string metadata = $"{election.Title}{election.Description}{startDateStr}{endDateStr}{election.OrganizerId}{candidatesJson}";
                    string hmacValue = CryptoHelper.CalculateHmac(metadata);

                    cmd.Parameters.AddWithValue("@title", election.Title);
                    cmd.Parameters.AddWithValue("@desc", election.Description);
                    cmd.Parameters.AddWithValue("@start", startDateStr);
                    cmd.Parameters.AddWithValue("@end", endDateStr);
                    cmd.Parameters.AddWithValue("@orgId", election.OrganizerId);
                    cmd.Parameters.AddWithValue("@candidates", candidatesJson);
                    cmd.Parameters.AddWithValue("@hmac", hmacValue);

                    cmd.ExecuteNonQuery();
                }
            }
        }

        public List<Election> GetElectionsByOrganizer(int organizerId)
        {
            var elections = new List<Election>();
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "SELECT * FROM Elections WHERE OrganizerId = @orgId ORDER BY Id DESC";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@orgId", organizerId);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var election = new Election
                            {
                                Id = Convert.ToInt32(reader["Id"]),
                                Title = reader["Title"].ToString() ?? "",
                                Description = reader["Description"].ToString() ?? "",
                                StartDate = DateTime.Parse(reader["StartDate"].ToString()),
                                EndDate = DateTime.Parse(reader["EndDate"].ToString()),
                                OrganizerId = Convert.ToInt32(reader["OrganizerId"])
                            };

                            string candidatesJson = reader["CandidatesJson"].ToString();
                            if (!string.IsNullOrEmpty(candidatesJson))
                            {
                                election.Candidates = JsonConvert.DeserializeObject<List<Candidate>>(candidatesJson);
                            }

                            string dbHmac = reader["Hmac"].ToString() ?? "";
                            string currentMetadata = $"{election.Title}{election.Description}{election.StartDate:o}{election.EndDate:o}{election.OrganizerId}{candidatesJson}";
                            string calculatedHmac = CryptoHelper.CalculateHmac(currentMetadata);

                            if (dbHmac != calculatedHmac)
                            {
                                election.Title = "[UPOZORENJE: Integritet narušen!] " + election.Title;
                            }

                            elections.Add(election);
                        }
                    }
                }
            }
            return elections;
        }

        public List<Election> GetActiveElections()
        {
            var elections = new List<Election>();
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "SELECT * FROM Elections";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            var election = new Election
                            {
                                Id = Convert.ToInt32(reader["Id"]),
                                Title = reader["Title"].ToString() ?? "",
                                Description = reader["Description"].ToString() ?? "",
                                StartDate = DateTime.Parse(reader["StartDate"].ToString()),
                                EndDate = DateTime.Parse(reader["EndDate"].ToString()),
                                OrganizerId = Convert.ToInt32(reader["OrganizerId"])
                            };

                            string candidatesJson = reader["CandidatesJson"].ToString();
                            if (!string.IsNullOrEmpty(candidatesJson))
                                election.Candidates = JsonConvert.DeserializeObject<List<Candidate>>(candidatesJson);

                            string dbHmac = reader["Hmac"].ToString() ?? "";
                            string currentMetadata = $"{election.Title}{election.Description}{election.StartDate:o}{election.EndDate:o}{election.OrganizerId}{candidatesJson}";
                            string calculatedHmac = CryptoHelper.CalculateHmac(currentMetadata);

                            if (dbHmac != calculatedHmac)
                            {
                                election.Title = "[UPOZORENJE: Integritet narušen!] " + election.Title;
                            }
                            if (election.IsActive)
                            {
                                elections.Add(election);
                            }
                        }
                    }
                }
            }
            return elections;
        }

        public bool HasUserVoted(int electionId, int voterId)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "SELECT COUNT(*) FROM Votes WHERE ElectionId = @eId AND VoterId = @vId";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@eId", electionId);
                    cmd.Parameters.AddWithValue("@vId", voterId);
                    return (long)cmd.ExecuteScalar() > 0;
                }
            }
        }

        public void AddVote(Vote vote)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = @"
                    INSERT INTO Votes (ElectionId, VoterId, EncryptedData, EncryptedSessionKey, DigitalSignature, Timestamp)
                    VALUES (@eId, @vId, @encData, @encKey, @sig, @time)";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@eId", vote.ElectionId);
                    cmd.Parameters.AddWithValue("@vId", vote.VoterId);
                    cmd.Parameters.AddWithValue("@encData", vote.EncryptedData);
                    cmd.Parameters.AddWithValue("@encKey", vote.EncryptedSessionKey);
                    cmd.Parameters.AddWithValue("@sig", vote.DigitalSignature);
                    cmd.Parameters.AddWithValue("@time", vote.Timestamp.ToString("o"));
                    cmd.ExecuteNonQuery();
                }
            }
        }

        public string GetUserCertificateSerialNumber(int userId)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "SELECT CertificateSerialNumber FROM Users WHERE Id = @id";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@id", userId);
                    return cmd.ExecuteScalar()?.ToString();
                }
            }
        }

        public List<Vote> GetVotesForElection(int electionId)
        {
            var votes = new List<Vote>();
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = "SELECT * FROM Votes WHERE ElectionId = @eId";
                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@eId", electionId);
                    using (var reader = cmd.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            votes.Add(new Vote
                            {
                                Id = Convert.ToInt32(reader["Id"]),
                                ElectionId = Convert.ToInt32(reader["ElectionId"]),
                                VoterId = Convert.ToInt32(reader["VoterId"]),
                                EncryptedData = reader["EncryptedData"].ToString() ?? "",
                                EncryptedSessionKey = reader["EncryptedSessionKey"].ToString() ?? "",
                                DigitalSignature = reader["DigitalSignature"].ToString() ?? "",
                                Timestamp = DateTime.Parse(reader["Timestamp"].ToString() ?? DateTime.UtcNow.ToString())
                            });
                        }
                    }
                }
            }
            return votes;
        }

        public string VerifyVote(string receiptSignature)
        {
            using (var conn = GetConnection())
            {
                conn.Open();
                string sql = @"
                    SELECT e.Title, v.Timestamp 
                    FROM Votes v 
                    JOIN Elections e ON v.ElectionId = e.Id 
                    WHERE v.DigitalSignature LIKE @sig";

                using (var cmd = new SQLiteCommand(sql, conn))
                {
                    cmd.Parameters.AddWithValue("@sig", receiptSignature + "%");
                    using (var reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return $"Pronađeno!\nVaš glas za glasanje '{reader["Title"]}' je bezbjedno zabilježen u bazi dana {reader["Timestamp"]}.\nSadržaj glasa je kriptografski zaštićen.";
                        }
                    }
                }
            }
            return null;
        }
    }
}