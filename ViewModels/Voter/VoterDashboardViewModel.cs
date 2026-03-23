using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EVotingSystem.Data;
using EVotingSystem.Models;
using EVotingSystem.Services.Cryptography;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System.Collections.ObjectModel;
using System.IO;
using System.Windows;

namespace EVotingSystem.ViewModels.Voter
{
    public partial class VoterDashboardViewModel : ObservableObject
    {
        private readonly DatabaseContext _dbContext;
        private readonly PkiService _pkiService;

        [ObservableProperty]
        private User currentUser;

        [ObservableProperty]
        private ObservableCollection<Election> activeElections;

        [ObservableProperty]
        private string receiptInput = string.Empty;

        public VoterDashboardViewModel(User user)
        {
            CurrentUser = user;
            _dbContext = new DatabaseContext();
            _pkiService = new PkiService();
            ActiveElections = new ObservableCollection<Election>();
            LoadActiveElections();
        }

        private void LoadActiveElections()
        {
            var elections = _dbContext.GetActiveElections();
            ActiveElections.Clear();
            foreach (var election in elections)
            {
                if (!_dbContext.HasUserVoted(election.Id, CurrentUser.Id))
                {
                    ActiveElections.Add(election);
                }
            }
        }

        [RelayCommand]
        private void Vote(Election selectedElection)
        {
            if (selectedElection == null)
                return;

            var selectedCandidate = selectedElection.Candidates.FirstOrDefault(c => c.IsSelected);
            if (selectedCandidate == null)
            {
                MessageBox.Show("Molimo odaberite opciju za glasanje.", "Greška", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (_dbContext.HasUserVoted(selectedElection.Id, CurrentUser.Id))
            {
                MessageBox.Show("Već ste glasali na ovim izborima.", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
                LoadActiveElections();
                return;
            }

            try
            {
                string encryptedVoteData = CryptoHelper.EncryptVoteDataWithAes(selectedCandidate.Name, out byte[] aesKey);

                string orgUsername = _dbContext.GetUsernameById(selectedElection.OrganizerId);
                string orgCertPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PKI_ROOT", "UserCerts", $"{orgUsername}.crt");

                using var orgReader = new PemReader(File.OpenText(orgCertPath));
                var orgPublicKey = ((X509Certificate)orgReader.ReadObject()).GetPublicKey();

                string encryptedSessionKey = CryptoHelper.EncryptAesKeyWithRsa(aesKey, orgPublicKey);

                string signature = CryptoHelper.SignVote(encryptedVoteData, encryptedSessionKey, AppSession.CurrentUserPrivateKey);

                string voterCertPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PKI_ROOT", "UserCerts", $"{CurrentUser.Username}.crt");
                using var voterReader = new PemReader(File.OpenText(voterCertPath));
                var voterPublicKey = ((X509Certificate)voterReader.ReadObject()).GetPublicKey();

                if (!CryptoHelper.VerifyVoteSignature(encryptedVoteData, encryptedSessionKey, signature, voterPublicKey))
                    throw new Exception("Digitalni potpis glasa nije validan.");

                string receiptPlain = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
                string receiptHash = CryptoHelper.GetSha256Hash(receiptPlain);

                DateTime now = DateTime.UtcNow;

                var vote = new Vote
                {
                    ElectionId = selectedElection.Id,
                    EncryptedData = encryptedVoteData,
                    EncryptedSessionKey = encryptedSessionKey,
                    ReceiptHash = receiptHash,
                    Timestamp = now
                };

                vote.BallotHmac = CryptoHelper.CalculateBallotHmac(
                    vote.ElectionId,
                    vote.EncryptedData,
                    vote.EncryptedSessionKey,
                    vote.ReceiptHash,
                    vote.Timestamp
                );

                var participation = new VotingParticipation
                {
                    ElectionId = selectedElection.Id,
                    VoterId = CurrentUser.Id,
                    Timestamp = now
                };

                _dbContext.AddVoteAndParticipation(vote, participation);

                MessageBox.Show(
                    $"Vaš glas je uspješno zabilježen!\n\n" +
                    $"Vaš receipt kod je:\n{receiptPlain}\n\n" +
                    $"Sačuvajte ovaj kod. Pomoću njega možete kasnije potvrditi da je glas upisan.",
                    "Glasanje uspješno",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                LoadActiveElections();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Došlo je do greške prilikom glasanja: {ex.Message}", "Kritična greška", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        private void VerifyMyVote()
        {
            if (string.IsNullOrWhiteSpace(ReceiptInput))
            {
                MessageBox.Show("Unesite kod (Receipt) koji ste dobili nakon glasanja.", "Upozorenje", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string verificationResult = _dbContext.VerifyVote(ReceiptInput);
            if (verificationResult != null)
            {
                MessageBox.Show(verificationResult, "Uspješna verifikacija", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show("Glas sa tim kodom nije pronađen u bazi podataka.", "Nepoznat kod", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}