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

                var orgCaCertPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PKI_ROOT", "OrgCA", "org.crt");
                var pemReader = new PemReader(File.OpenText(orgCaCertPath));
                var orgPublicKey = ((X509Certificate)pemReader.ReadObject()).GetPublicKey();

                string encryptedSessionKey = CryptoHelper.EncryptAesKeyWithRsa(aesKey, orgPublicKey);

                string signature = CryptoHelper.SignVote(encryptedVoteData, encryptedSessionKey, AppSession.CurrentUserPrivateKey);

                var vote = new Vote
                {
                    ElectionId = selectedElection.Id,
                    VoterId = CurrentUser.Id,
                    EncryptedData = encryptedVoteData,
                    EncryptedSessionKey = encryptedSessionKey,
                    DigitalSignature = signature,
                    Timestamp = DateTime.UtcNow
                };

                _dbContext.AddVote(vote);

                string receipt = signature.Length > 40 ? signature.Substring(0, 40) : signature;

                MessageBox.Show(
                    $"Vaš glas je uspješno zabilježen, enkriptovan i digitalno potpisan!\n\n" +
                    $"Vaš jedinstveni kod za verifikaciju (Receipt) je:\n\n{receipt}\n\n" +
                    $"Obavezno kopirajte i sačuvajte ovaj kod! Pomoću njega možete potvrditi da je vaš glas u bazi, bez otkrivanja za koga ste glasali.",
                    "Glasanje Uspješno",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);

                LoadActiveElections();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Došlo je do greške prilikom glasanja: {ex.Message}", "Kritična Greška", MessageBoxButton.OK, MessageBoxImage.Error);
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