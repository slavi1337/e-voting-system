using EVotingSystem.Models;
using EVotingSystem.ViewModels.Organizer;
using System.Windows;

namespace EVotingSystem.Views.Organizer
{
    public partial class OrganizerDashboardView : Window
    {
        public OrganizerDashboardView(User user)
        {
            InitializeComponent();
            DataContext = new OrganizerDashboardViewModel(user);
        }
    }
}