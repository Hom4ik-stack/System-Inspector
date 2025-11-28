using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Linq;

namespace SecurityShield.Services
{
    public class ReportService : IReportService
    {
        // Метод GenerateHtmlReportAsync внутри ReportService

        public async Task<string> GenerateHtmlReportAsync(ReportData data)
        {
            return await Task.Run(() =>
            {
                var sb = new StringBuilder();

                // HTML Header with CSS
                sb.AppendLine("<!DOCTYPE html><html lang='ru'><head><meta charset='UTF-8'>");
                sb.AppendLine("<title>Security Shield Report</title>");
                sb.AppendLine("<style>");
                sb.AppendLine("body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }");
                sb.AppendLine(".container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }");
                sb.AppendLine("h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }");
                sb.AppendLine("h2 { color: #34495e; margin-top: 30px; }");
                sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-top: 10px; }");
                sb.AppendLine("th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }");
                sb.AppendLine("th { background-color: #f8f9fa; font-weight: 600; }");
                sb.AppendLine(".status-ok { color: green; font-weight: bold; }");
                sb.AppendLine(".status-risk { color: red; font-weight: bold; }");
                sb.AppendLine(".status-warning { color: orange; font-weight: bold; }");
                sb.AppendLine("</style></head><body>");

                sb.AppendLine("<div class='container'>");
                sb.AppendLine($"<h1>🛡 Отчет о безопасности системы</h1>");
                sb.AppendLine($"<p><strong>Дата:</strong> {data.ReportDate}</p>");
                sb.AppendLine($"<p><strong>Компьютер:</strong> {data.SystemInfo?.ComputerName} / {data.SystemInfo?.UserName}</p>");
                sb.AppendLine($"<p><strong>Оценка безопасности:</strong> {data.OverallSecurityStatus}</p>");

                // Секция: Угрозы
                if (data.Threats != null && data.Threats.Any())
                {
                    sb.AppendLine("<h2>🚨 Обнаруженные угрозы</h2>");
                    sb.AppendLine("<table><tr><th>Угроза</th><th>Важность</th><th>Рекомендация</th></tr>");
                    foreach (var t in data.Threats)
                    {
                        sb.AppendLine($"<tr><td>{t.Name}</td><td class='status-risk'>{t.Severity}</td><td>{t.Recommendation}</td></tr>");
                    }
                    sb.AppendLine("</table>");
                }

                // Секция: Проверки безопасности
                if (data.SecurityChecks != null && data.SecurityChecks.Any())
                {
                    sb.AppendLine("<h2>🛡 Проверки безопасности</h2>");
                    sb.AppendLine("<table><tr><th>Проверка</th><th>Статус</th><th>Детали</th></tr>");
                    foreach (var c in data.SecurityChecks)
                    {
                        string cls = c.IsCritical ? "status-risk" : (c.Status.Contains("ОК") ? "status-ok" : "status-warning");
                        sb.AppendLine($"<tr><td>{c.CheckName}</td><td class='{cls}'>{c.Status}</td><td>{c.Details}</td></tr>");
                    }
                    sb.AppendLine("</table>");
                }

                // Секция: Устройства
                if (data.Devices != null)
                {
                    sb.AppendLine("<h2>🔌 Подключенные устройства</h2>");
                    sb.AppendLine("<table><tr><th>Имя</th><th>Тип</th><th>Безопасность</th></tr>");
                    foreach (var d in data.Devices)
                    {
                        string safe = d.IsSafe ? "Безопасно" : "⚠ Требует внимания";
                        string cls = d.IsSafe ? "status-ok" : "status-warning";
                        sb.AppendLine($"<tr><td>{d.Name}</td><td>{d.Category}</td><td class='{cls}'>{safe} <br/><small>{d.SafetyWarning}</small></td></tr>");
                    }
                    sb.AppendLine("</table>");
                }

                sb.AppendLine("</div></body></html>");

                return sb.ToString();
            });
        }
        public async Task<bool> ExportReportToFileAsync(string filePath, ReportData data)
        {
            try
            {
                var htmlContent = await GenerateHtmlReportAsync(data);
                await File.WriteAllTextAsync(filePath, htmlContent, Encoding.UTF8);
                return true;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Ошибка сохранения отчета: {ex.Message}");
                return false;
            }
        }

      
    }
}