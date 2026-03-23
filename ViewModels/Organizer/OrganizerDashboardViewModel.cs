using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EVotingSystem.Data;
using EVotingSystem.Models;
using EVotingSystem.Services.Cryptography;
using System.Collections.ObjectModel;
using System.IO;
using System.Security.Cryptography;
using System.Windows;

namespace EVotingSystem.ViewModels.Organizer
{
    public partial class OrganizerDashboardViewModel : ObservableObject
    {
        private readonly DatabaseContext _dbContext;

        [ObservableProperty]
        private User currentUser;

        [ObservableProperty] private string electionTitle = string.Empty;
        [ObservableProperty] private string electionDescription = string.Empty;
        [ObservableProperty] private DateTime startDate = DateTime.Today;
        [ObservableProperty] private DateTime startTime = DateTime.Now;
        [ObservableProperty] private DateTime endDate = DateTime.Today.AddDays(7);
        [ObservableProperty] private DateTime endTime = DateTime.Now;
        [ObservableProperty] private string candidatesInput = string.Empty;
        [ObservableProperty] private ObservableCollection<Election> myElections = new ObservableCollection<Election>();

        public OrganizerDashboardViewModel(User user)
        {
            CurrentUser = user;
            _dbContext = new DatabaseContext();
            LoadElections();
        }

        [RelayCommand]
        private void CreateElection()
        {
            if (string.IsNullOrWhiteSpace(ElectionTitle) || string.IsNullOrWhiteSpace(CandidatesInput))
            {
                MessageBox.Show("Naslov i lista kandidata su obavezni.", "Greška", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            DateTime fullStart = StartDate.Date.Add(StartTime.TimeOfDay);
            DateTime fullEnd = EndDate.Date.Add(EndTime.TimeOfDay);

            if (fullEnd <= fullStart)
            {
                MessageBox.Show("Vrijeme završetka mora biti nakon vremena početka.", "Greška", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var candidateNames = CandidatesInput.Split(',')
                                                .Select(name => name.Trim())
                                                .Where(name => !string.IsNullOrEmpty(name))
                                                .ToList();

            if (candidateNames.Count < 2 || candidateNames.Count > 5)
            {
                MessageBox.Show("Morate unijeti između 2 i 5 kandidata, odvojenih zarezom.", "Greška", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var election = new Election
            {
                Title = ElectionTitle,
                Description = ElectionDescription,
                StartDate = fullStart,
                EndDate = fullEnd,
                OrganizerId = CurrentUser.Id,
                Candidates = candidateNames.Select((name, index) => new Candidate { Id = index + 1, Name = name }).ToList()
            };

            try
            {
                _dbContext.AddElection(election);
                MessageBox.Show("Novo glasanje je uspješno kreirano!", "Uspjeh", MessageBoxButton.OK, MessageBoxImage.Information);

                ElectionTitle = string.Empty;
                ElectionDescription = string.Empty;
                CandidatesInput = string.Empty;
                StartDate = DateTime.Today;
                EndDate = DateTime.Today.AddDays(7);
                LoadElections();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Došlo je do greške prilikom čuvanja u bazu: {ex.Message}", "Greška", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        public void LoadElections()
        {
            var electionsFromDb = _dbContext.GetElectionsByOrganizer(CurrentUser.Id);
            MyElections.Clear();
            foreach (var el in electionsFromDb)
            {
                MyElections.Add(el);
            }
        }
        [RelayCommand]
        private void CountVotes(Election election)
        {
            if (election == null)
                return;

            try
            {
                var orgPrivateKey = AppSession.CurrentUserPrivateKey;
                if (orgPrivateKey == null)
                    throw new Exception("Privatni ključ organizatora nije učitan.");

                var votes = _dbContext.GetVotesForElection(election.Id);
                var results = election.Candidates.ToDictionary(c => c.Name, c => 0);
                int validVotes = 0;
                int rejectedVotes = 0;

                foreach (var vote in votes)
                {
                    try
                    {
                        string expectedBallotHmac = CryptoHelper.CalculateBallotHmac(
                            vote.ElectionId,
                            vote.EncryptedData,
                            vote.EncryptedSessionKey,
                            vote.ReceiptHash,
                            vote.Timestamp
                        );

                        if (!CryptographicOperations.FixedTimeEquals(
                                Convert.FromBase64String(expectedBallotHmac),
                                Convert.FromBase64String(vote.BallotHmac)))
                        {
                            rejectedVotes++;
                            continue;
                        }

                        byte[] aesKey = CryptoHelper.DecryptAesKeyWithRsa(vote.EncryptedSessionKey, orgPrivateKey);
                        string candidateName = CryptoHelper.DecryptVoteDataWithAes(vote.EncryptedData, aesKey);

                        if (results.ContainsKey(candidateName))
                        {
                            results[candidateName]++;
                            validVotes++;
                        }
                        else
                        {
                            rejectedVotes++;
                        }
                    }
                    catch
                    {
                        rejectedVotes++;
                    }
                }

                string reportData = $"IZVJEŠTAJ O GLASANJU\n" +
                                    $"Glasanje: {election.Title}\n" +
                                    $"Datum kreiranja izvještaja: {DateTime.Now}\n\n";

                foreach (var res in results)
                    reportData += $"{res.Key}: {res.Value} glasova\n";

                reportData += $"\nUkupno validnih glasova: {validVotes}";
                reportData += $"\nOdbačenih glasova: {rejectedVotes}";

                string reportSignature = CryptoHelper.SignReport(reportData, orgPrivateKey);
                string finalReport = reportData + "\n\n--- DIGITALNI POTPIS ORGANIZATORA ---\n" + reportSignature;

                string reportPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, $"Izvjestaj_Glasanja_{election.Id}.txt");
                File.WriteAllText(reportPath, finalReport);

                MessageBox.Show(
                    $"Rezultati uspješno izbrojani!\n\nIzvještaj je sačuvan na:\n{reportPath}",
                    "Prebrojavanje završeno",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Greška prilikom brojanja glasova: {ex.Message}", "Greška", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}