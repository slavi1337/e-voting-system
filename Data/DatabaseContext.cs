using System.Data.SQLite;
using System.IO;

namespace EVotingSystem.Data
{
    public class DatabaseContext
    {
        private const string DbName = "evoting_database.sqlite";
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
                            LastName TEXT
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
    }
}