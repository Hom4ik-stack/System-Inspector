namespace SecurityShield.Models
{
    public class DefenderStatus
    {
        public bool IsEnabled { get; set; }
        public bool IsRealTimeProtectionEnabled { get; set; }
        public bool IsCloudProtectionEnabled { get; set; }
        public bool IsTamperProtectionEnabled { get; set; }
        public string AntivirusStatus { get; set; } = "Неизвестно";
        public string LastScanTime { get; set; } = "Неизвестно";
        public string DefinitionVersion { get; set; } = "Неизвестно";
        public bool IsFirewallEnabled { get; set; }
    }
}