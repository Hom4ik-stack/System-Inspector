using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
  
    public class SoftwareInfo : ObservableObject
    {
        public string DisplayName { get; set; } = string.Empty;
        

        public string DisplayVersion { get; set; } = string.Empty;
       

        public string Publisher { get; set; } = string.Empty;
      

        public string InstallDate { get; set; } = string.Empty;
       

        public string InstallLocation { get; set; } = string.Empty;
    
    }
}