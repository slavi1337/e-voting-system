using CommunityToolkit.Mvvm.ComponentModel;
using EVotingSystem.Models;

namespace EVotingSystem.ViewModels.Voter
{
    public partial class VoterDashboardViewModel : ObservableObject
    {
        [ObservableProperty]
        private User currentUser;

        public VoterDashboardViewModel(User user)
        {
            CurrentUser = user;
        }
    }
}