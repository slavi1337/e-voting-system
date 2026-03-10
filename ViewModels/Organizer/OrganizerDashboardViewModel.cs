using CommunityToolkit.Mvvm.ComponentModel;
using EVotingSystem.Models;

namespace EVotingSystem.ViewModels.Organizer
{
    public partial class OrganizerDashboardViewModel : ObservableObject
    {
        [ObservableProperty]
        private User currentUser;

        public OrganizerDashboardViewModel(User user)
        {
            CurrentUser = user;
        }
    }
}