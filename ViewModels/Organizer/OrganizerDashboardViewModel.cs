using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using EVotingSystem.Data;
using EVotingSystem.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows;
using System.Collections.ObjectModel;

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
        [ObservableProperty] private DateTime endDate = DateTime.Today.AddDays(7);
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

            if (EndDate <= StartDate)
            {
                MessageBox.Show("Datum završetka mora biti nakon datuma početka.", "Greška", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                StartDate = StartDate,
                EndDate = EndDate,
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

            if (!election.IsFinished)
            {
                MessageBox.Show("Ne možete pokrenuti brojanje glasova dok se glasanje zvanično ne završi!", "Upozorenje", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            MessageBox.Show($"Brojanje glasova za '{election.Title}' će biti uskoro implementirano.\nOvdje će se koristiti Vaš privatni RSA ključ!", "Info", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}