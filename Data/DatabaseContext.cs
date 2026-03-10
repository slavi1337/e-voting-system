using System.Data.SQLite;
using System.IO;
using EVotingSystem.Models;

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
                            CandidatesJson TEXT
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
    }
}