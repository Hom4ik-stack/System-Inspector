using CommunityToolkit.Mvvm.ComponentModel;
using System;
using System.Linq;

namespace SecurityShield.Models
{
    public partial class ProcessInfo : ObservableObject
    {
        [ObservableProperty]
        private string _name = string.Empty;

        [ObservableProperty]
        private int _id;

        [ObservableProperty]
        private double _memoryMB;

        [ObservableProperty]
        private double _cpu;

        [ObservableProperty]
        private string _processPath = string.Empty;

        [ObservableProperty]
        private string _windowTitle = string.Empty;

        [ObservableProperty]
        private bool _isUserProcess;

    
        public ProcessInfo() { }

        public ProcessInfo(string name, int id, double memoryMB, double cpu, string processPath, string windowTitle)
        {
            _name = name;
            _id = id;
            _memoryMB = memoryMB;
            _cpu = cpu;
            _processPath = processPath;
            _windowTitle = windowTitle;
            _isUserProcess = CheckIsUserProcess();
        }

        public bool CheckIsUserProcess()
        {
            if (string.IsNullOrEmpty(Name))
                return false;

            string processName = Name.ToLower();

            // Критические системные процессы Windows, которые НЕЛЬЗЯ завершать
            var criticalSystemProcesses = new[]
            {
                "system", "smss", "csrss", "wininit", "services", "lsass",
                "svchost", "winlogon", "fontdrvhost", "dwm", "taskhostw"
            };

            // Если процесс критически важный - запрещаем завершение
            if (criticalSystemProcesses.Any(critical =>
                processName.Equals(critical) || processName.StartsWith(critical + ".")))
                return false;

            // Процессы, связанные с системными службами Windows
            var systemServiceProcesses = new[]
            {
                "spoolsv", "taskeng", "searchindexer", "searchui", "runtimebroker",
                "sihost", "ctfmon", "conhost", "audiodg", "securityhealthservice",
                "msmpeng", "defender", "mrt", "wmiprvse", "dllhost", "dasHost"
            };

            // Если это системная служба - запрещаем завершение
            if (systemServiceProcesses.Any(service =>
                processName.Equals(service) || processName.StartsWith(service + ".")))
                return false;

            // Процессы Windows, которые обычно можно завершать, но с осторожностью
            var windowsProcesses = new[]
            {
                "explorer", "notepad", "calc", "mspaint", "write", "snippingtool"
            };

            // Проверяем путь к процессу для определения системности
            if (!string.IsNullOrEmpty(ProcessPath) && !ProcessPath.Contains("Нет доступа"))
            {
                var systemPaths = new[]
                {
                    "C:\\Windows\\System32",
                    "C:\\Windows\\SysWOW64",
                    "C:\\Windows\\SystemApps",
                    "C:\\Program Files\\Windows"
                };

                // Если процесс находится в системной директории - скорее всего системный
                if (systemPaths.Any(path => ProcessPath.StartsWith(path, StringComparison.OrdinalIgnoreCase)))
                    return false;
            }

            // Все остальные процессы считаем пользовательскими (с осторожностью)
            return true;
        }
    }
}