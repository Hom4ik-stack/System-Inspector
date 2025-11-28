using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
  
    public partial class NetworkConnectionInfo : ObservableObject
    {
        
        [ObservableProperty]
        public string _localAddress = string.Empty;

        [ObservableProperty]
        public int _localPort;

        [ObservableProperty]
        public string _remoteAddress = string.Empty;

        [ObservableProperty]
        public int _remotePort;

        [ObservableProperty]
        public string _state = string.Empty;

        [ObservableProperty]
        public string _processName = "N/A";

        [ObservableProperty]
        public int _processId;

        [ObservableProperty]
        public string _remotePortDescription = string.Empty;

        [ObservableProperty]
        public string _localPortDescription = string.Empty;

        [ObservableProperty]
        public string _connectionPurpose = string.Empty;
    }
}