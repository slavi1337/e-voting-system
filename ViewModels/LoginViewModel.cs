using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EVotingSystem.Data;
using EVotingSystem.Models;
using EVotingSystem.Services.Cryptography;
using Microsoft.Win32;
using System.IO;
using System.Windows;
using System.Windows.Controls;

namespace EVotingSystem.ViewModels
{
    public partial class LoginViewModel : ObservableObject
    {
        private readonly DatabaseContext _dbContext;
        private readonly PkiService _pkiService;

        public LoginViewModel()
        {
            _dbContext = new DatabaseContext();
            _pkiService = new PkiService();
        }

        [ObservableProperty] private bool isStepOneVisible = true;
        [ObservableProperty] private bool isStepTwoVisible = false;

        [ObservableProperty] private string selectedCertificatePath = "Nije odabran sertifikat";
        [ObservableProperty] private string username = string.Empty;

        private string _loadedCertSerialNumber = string.Empty;

        [RelayCommand]
        public void SelectCertificate()
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "PKCS#12 Sertifikati (*.p12)|*.p12|Svi fajlovi (*.*)|*.*",
                Title = "Odaberite vaš digitalni sertifikat"
            };

            if (openFileDialog.ShowDialog() == true)
            {
                SelectedCertificatePath = openFileDialog.FileName;
            }
        }

        [RelayCommand]
        public void ValidateCertificate(object parameter)
        {
            if (parameter is not PasswordBox passwordBox)
                return;
            string certPassword = passwordBox.Password;

            if (!File.Exists(SelectedCertificatePath))
            {
                MessageBox.Show("Molimo odaberite validan .p12 fajl.");
                return;
            }

            bool isValid = _pkiService.ValidateAndExtractCertificate(SelectedCertificatePath, certPassword, out string serialNumber, out string errorMessage);

            if (isValid)
            {
                _loadedCertSerialNumber = serialNumber;
                MessageBox.Show("Sertifikat uspješno validiran!\nMožete preći na Korak 2 (Kredencijali).", "Korak 1 Uspješan", MessageBoxButton.OK, MessageBoxImage.Information);
                IsStepOneVisible = false; 
                IsStepTwoVisible = true;
            }
            else
            {
                _loadedCertSerialNumber = string.Empty;
                MessageBox.Show($"Neispravan sertifikat!\nRazlog: {errorMessage}", "Greška", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        [RelayCommand]
        public void Login(object parameter)
        {
            if (parameter is not PasswordBox passwordBox)
                return;
            string appPassword = passwordBox.Password;

            if (string.IsNullOrEmpty(_loadedCertSerialNumber))
            {
                MessageBox.Show("Prvo morate učitati i validirati svoj sertifikat (KORAK 1).", "Upozorenje", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var user = _dbContext.GetUserByUsername(Username);
            if (user == null)
            {
                MessageBox.Show("Korisnik ne postoji.");
                return;
            }

            if (user.IsRevoked)
            {
                MessageBox.Show("Vaš nalog je BLOKIRAN, a sertifikat povučen zbog previše neuspješnih prijava.", "Blokirano", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (user.CertificateSerialNumber != _loadedCertSerialNumber)
            {
                MessageBox.Show("Učitani sertifikat ne pripada ovom korisničkom nalogu!", "Sigurnosna greška", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string hashedInput = CryptoHelper.ComputeSha256Hash(appPassword);
            if (user.PasswordHash != hashedInput)
            {
                user.FailedLoginAttempts++;

                if (user.FailedLoginAttempts >= 3)
                {
                    user.IsRevoked = true; 
                    _pkiService.RevokeCertificate(user.CertificateSerialNumber, user.Role == UserRole.Organizer);
                    _dbContext.UpdateUser(user);

                    MessageBox.Show("Unijeli ste pogrešnu lozinku 3 puta. Vaš nalog je trajno blokiran, a sertifikat povučen!", "Sigurnosno blokiranje", MessageBoxButton.OK, MessageBoxImage.Stop);
                }
                else
                {
                    _dbContext.UpdateUser(user);
                    MessageBox.Show($"Pogrešna lozinka! Preostalo pokušaja: {3 - user.FailedLoginAttempts}", "Greška", MessageBoxButton.OK, MessageBoxImage.Warning);
                }
                return;
            }

            user.FailedLoginAttempts = 0;
            _dbContext.UpdateUser(user);

            MessageBox.Show($"Uspješna prijava!\nDobrodošli, {user.FirstName} {user.LastName} ({user.Role}).", "Prijava uspješna", MessageBoxButton.OK, MessageBoxImage.Information);

            if (user.Role == UserRole.Organizer)
            {
                var dashboard = new Views.Organizer.OrganizerDashboardView(user);
                dashboard.Show();
            }
            else 
            {
                var dashboard = new Views.Voter.VoterDashboardView(user);
                dashboard.Show();
            }

            foreach (Window window in Application.Current.Windows)
            {
                if (window.DataContext == this)
                {
                    window.Close();
                    break;
                }
            }
        }
        [RelayCommand]
        public void GoToRegister()
        {
            var registerView = new Views.RegisterView();
            registerView.Show();

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