using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityShield.Models
{
    public class SecurityScanResult
    {
        public DateTime ScanTime { get; set; } = DateTime.Now;
        public int TotalThreats { get; set; }
        public int CriticalIssues { get; set; }
        public int Warnings { get; set; }
        public string OverallStatus { get; set; } = "Не проверено";
        public List<SecurityThreat> Threats { get; set; } = new List<SecurityThreat>();
        public List<SecurityCheck> SecurityChecks { get; set; } = new List<SecurityCheck>();
    }
}
