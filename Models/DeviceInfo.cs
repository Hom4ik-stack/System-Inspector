using CommunityToolkit.Mvvm.ComponentModel;

namespace SecurityShield.Models
{
    public class DeviceInfo
    {
        public string Name { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Status { get; set; } = string.Empty;
        public string Manufacturer { get; set; } = string.Empty;
        public string DeviceID { get; set; } = string.Empty;
        public string DriverVersion { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string InterfaceType { get; set; } = string.Empty;
        public string MediaType { get; set; } = string.Empty;
        public ulong Size { get; set; }
        public string SizeFormatted => Size > 0 ? $"{(Size / 1024.0 / 1024.0 / 1024.0):F2} GB" : "N/A";
        public bool IsRemovable { get; set; }
        public bool IsSafe { get; set; } = true;
        public string SafetyWarning { get; set; } = string.Empty;
        public string VulnerabilityStatus { get; set; } = "Не проверено";

        public string ProcessorCores { get; set; } = string.Empty;
        public string ProcessorFrequency { get; set; } = string.Empty;
        public string DiskType { get; set; } = string.Empty;
        public string ConnectionProtocol { get; set; } = string.Empty;
        public string FirmwareVersion { get; set; } = string.Empty;
 
    }
}