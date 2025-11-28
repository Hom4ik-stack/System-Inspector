using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityShield.Models
{
    public class SecurityCheck
    {
        public string CheckName { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string Status { get; set; } = "Не проверено";
        public string Details { get; set; } = string.Empty;
        public string Recommendation { get; set; } = string.Empty;
        public bool IsCritical { get; set; }
    }
}
