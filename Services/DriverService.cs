using SecurityShield.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Management;
using System.Threading.Tasks;
using System.Windows;

namespace SecurityShield.Services
{
    public class DriverService : IDriverService
    {
        public List<DriverInfo> GetInstalledDrivers()
        {
            var drivers = new List<DriverInfo>();
            try
            {
                using var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_PnPSignedDriver");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var deviceName = obj["DeviceName"]?.ToString();
                    var deviceClass = obj["DeviceClass"]?.ToString() ?? "UNKNOWN";

                 if (string.IsNullOrEmpty(deviceName) ||
                        deviceClass.Equals("SOFTWAREDEVICE", StringComparison.OrdinalIgnoreCase) ||
                        deviceClass.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
                        deviceClass.Equals("USB", StringComparison.OrdinalIgnoreCase)) 
                    {
                        continue;
                    }

                    var driver = new DriverInfo
                    {
                        Name = deviceName,
                        Description = obj["Description"]?.ToString() ?? "",
                        Version = obj["DriverVersion"]?.ToString() ?? "Unknown",
                        Manufacturer = obj["Manufacturer"]?.ToString() ?? "Unknown",
                        Date = ManagementDateTimeConverter.ToDateTime(obj["DriverDate"]?.ToString() ?? "").ToString("dd.MM.yyyy"), // Форматируем дату
                        Class = deviceClass
                    };
                    // Проверка цифровой подписи
                    driver.DigitalSignature = CheckDigitalSignature(obj);
                    drivers.Add(driver);
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Ошибка получения драйверов: {ex.Message}");
            }
            return drivers;
        }

        public List<DriverInfo> CheckOutdatedDrivers()
        {
            var outdatedDrivers = new List<DriverInfo>();
            var allDrivers = GetInstalledDrivers();

            foreach (var driver in allDrivers)
            {
                if (IsDriverOutdated(driver))
                {
                    driver.IsOutdated = true;
                    driver.UpdateStatus = "Требуется обновление";
                    driver.RiskLevel = GetRiskLevel(driver);
                    outdatedDrivers.Add(driver);
                }
                else
                {
                    driver.IsOutdated = false;
                    driver.UpdateStatus = "Актуальный";
                    driver.RiskLevel = "Низкий";
                }
            }
            return outdatedDrivers;
        }

    

        private bool IsDriverOutdated(DriverInfo driver)
        {
            int outdatedScore = 0;

            // 1. Критическая уязвимость: Драйвер не подписан
            if (driver.DigitalSignature != "Подписан")
            {
                outdatedScore += 3;
            }

   
            if (driver.Manufacturer.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
            {
               
                return outdatedScore > 0; 
            }

       
            if (DateTime.TryParse(driver.Date, out var driverDate))
            {
                var yearsOld = (DateTime.Now - driverDate).TotalDays / 365;
                
                if (yearsOld > 5) outdatedScore += 2;
            }

            // 4. Неизвестный производитель
            if (driver.Manufacturer.Contains("Unknown", StringComparison.OrdinalIgnoreCase))
            {
                outdatedScore += 1;
            }

            return outdatedScore >= 2; // Если набрали 2+ балла - драйвер устаревший
        }

        private string GetRiskLevel(DriverInfo driver)
        {
            int riskScore = 0;

            if (driver.DigitalSignature != "Подписан") riskScore += 2;
            if (driver.Manufacturer.Contains("Unknown", StringComparison.OrdinalIgnoreCase)) riskScore += 1;
            if (driver.Class.Contains("NETWORK", StringComparison.OrdinalIgnoreCase) ||
                driver.Class.Contains("DISPLAY", StringComparison.OrdinalIgnoreCase))
                riskScore += 1;

            return riskScore >= 3 ? "Критический" : riskScore >= 2 ? "Высокий" : "Средний";
        }

        private string CheckDigitalSignature(ManagementObject driver)
        {
            try
            {
                var isSigned = driver["IsSigned"]?.ToString();
                return isSigned == "True" ? "Подписан" : "Не подписан";
            }
            catch
            {
                return "Неизвестно";
            }
        }

      }
}