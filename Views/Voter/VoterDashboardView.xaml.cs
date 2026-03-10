using EVotingSystem.Models;
using EVotingSystem.ViewModels.Voter;
using System.Windows;

namespace EVotingSystem.Views.Voter
{
    public partial class VoterDashboardView : Window
    {
        public VoterDashboardView(User user)
        {
            InitializeComponent();
            DataContext = new VoterDashboardViewModel(user);
        }
    }
}