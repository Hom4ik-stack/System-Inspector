using SecurityShield.Models;
using System.Threading.Tasks;

namespace SecurityShield.Services
{
    public interface IReportService
    {
        Task<string> GenerateHtmlReportAsync(ReportData data);
        Task<bool> ExportReportToFileAsync(string filePath, ReportData data);
   
    }
}