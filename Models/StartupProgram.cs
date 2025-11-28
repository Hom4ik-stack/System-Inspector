using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
    public class StartupProgram : ObservableObject
    {
        public string Name { get; set; } = string.Empty;
       

        public string Command { get; set; } = string.Empty;
      

        public string Location { get; set; } = string.Empty;
       

        public string User { get; set; } = string.Empty;
      
    }
}