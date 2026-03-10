using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EVotingSystem.Data;
using EVotingSystem.Models;
using EVotingSystem.Services.Cryptography;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Windows;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;

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

                MessageBox.Show("Vaš glas je uspješno zabilježen, enkriptovan i digitalno potpisan!", "Glasanje Uspješno", MessageBoxButton.OK, MessageBoxImage.Information);

                LoadActiveElections();
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Došlo je do greške prilikom glasanja: {ex.Message}", "Kritična Greška", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
    }
}