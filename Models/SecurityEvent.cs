namespace SecurityShield.Models
{
    public class SecurityEvent
    {
        public DateTime TimeGenerated { get; set; }
        public string EventType { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string Severity { get; set; } = "Информация";
    }
}