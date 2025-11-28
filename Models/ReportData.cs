using System.Collections.Generic;
namespace SecurityShield.Models
{
    public class ReportData
    {
        public SystemInfo SystemInfo { get; set; } = new SystemInfo();
        public List<ProcessInfo> TopProcesses { get; set; } = new List<ProcessInfo>();
        public List<DriveInfoModel> Drives { get; set; } = new List<DriveInfoModel>();
        public List<DriverInfo> Drivers { get; set; } = new List<DriverInfo>();
        public List<DeviceInfo> Devices { get; set; } = new List<DeviceInfo>();
        public List<SecurityCheck> SecurityChecks { get; set; } = new List<SecurityCheck>();
        public List<SecurityThreat> Threats { get; set; } = new List<SecurityThreat>();
        public List<SecurityVulnerability> Vulnerabilities { get; set; } = new List<SecurityVulnerability>();

        public string ReportDate { get; set; } = string.Empty;
        public string ScanDuration { get; set; } = string.Empty;
        public int TotalSecurityIssues { get; set; }
        public int CriticalIssuesCount { get; set; }
        public int HighIssuesCount { get; set; }
        public string OverallSecurityStatus { get; set; } = "Неизвестно";
    }
}