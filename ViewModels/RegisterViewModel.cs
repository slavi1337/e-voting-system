using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EVotingSystem.Data;
using EVotingSystem.Models;
using EVotingSystem.Services.Cryptography;
using System.Windows;

namespace EVotingSystem.ViewModels
{
    public partial class RegisterViewModel : ObservableObject
    {
        private readonly DatabaseContext _dbContext;
        private readonly PkiService _pkiService;

        public RegisterViewModel()
        {
            _dbContext = new DatabaseContext();
            _pkiService = new PkiService();
        }

        [ObservableProperty] private string username = string.Empty;
        [ObservableProperty] private string password = string.Empty;

        [ObservableProperty] private string firstName = string.Empty;
        [ObservableProperty] private string lastName = string.Empty;
        [ObservableProperty] private string jmbg = string.Empty;

        [ObservableProperty] private string organizationName = string.Empty;
        [ObservableProperty] private string orgIdNumber = string.Empty;

        [ObservableProperty] private bool isVoterSelected = true;
        [ObservableProperty] private bool isOrganizerSelected = false;

        [RelayCommand]
        public void SelectVoter()
        {
            IsVoterSelected = true;
            IsOrganizerSelected = false;
        }

        [RelayCommand]
        public void SelectOrganizer()
        {
            IsVoterSelected = false;
            IsOrganizerSelected = true;
        }

        [RelayCommand]
        public void Register()
        {
            if (string.IsNullOrWhiteSpace(Username) || string.IsNullOrWhiteSpace(Password))
            {
                MessageBox.Show("Korisničko ime i lozinka su obavezni!");
                return;
            }

            if (_dbContext.UserExists(Username))
            {
                MessageBox.Show("Korisničko ime već postoji!");
                return;
            }

            string commonName = IsOrganizerSelected ? OrganizationName : $"{FirstName} {LastName}";
            if (string.IsNullOrWhiteSpace(commonName))
                commonName = Username;

            try
            {
                string p12Path = _pkiService.RegisterUserCertificate(
                    Username,
                    Password,
                    commonName,
                    IsOrganizerSelected,
                    out string serialNumber
                );

                var newUser = new User
                {
                    Username = Username,
                    PasswordHash = CryptoHelper.ComputeSha256Hash(Password),
                    Role = IsOrganizerSelected ? UserRole.Organizer : UserRole.Voter,
                    CertificateSerialNumber = serialNumber,

                    FirstName = FirstName,
                    LastName = LastName,
                    JMBG = Jmbg,
                    OrganizationName = OrganizationName,
                    OrgIdNumber = OrgIdNumber
                };

                _dbContext.AddUser(newUser);

                MessageBox.Show($"Registracija uspješna!\n\nVaš digitalni sertifikat je kreiran:\n{p12Path}\n\nČUVAJTE OVAJ FAJL! Trebaće vam za prijavu.");

                var loginView = new Views.LoginView();
                loginView.Show();

                foreach (Window window in Application.Current.Windows)
                {
                    if (window.DataContext == this)
                    {
                        window.Close();
                        break;
                    }
                }
            }
            catch (System.Exception ex)
            {
                MessageBox.Show($"Greška prilikom registracije:\n{ex.Message}\n\nDetalji:\n{ex.StackTrace}",
                                "Kritična Greška",
                                MessageBoxButton.OK,
                                MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        public void GoToLogin()
        {
            var loginView = new Views.LoginView();
            loginView.Show();

            foreach (Window window in Application.Current.Windows)
            {
                if (window.DataContext == this)
                {
                    window.Close();
                    break;
                }
            }
        }
    }
}