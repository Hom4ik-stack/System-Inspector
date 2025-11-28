using SecurityShield.Models;
using System.Collections.Generic;

namespace SecurityShield.Services
{
    public interface ISystemInfoService
    {
        List<DriveInfoModel> GetDriveInfo();
        List<ProcessInfo> GetRunningProcesses();
        List<ProcessInfo> GetUserProcesses();
        SystemInfo GetDetailedSystemInfo();
        double GetCurrentCpuUsage();
        bool KillProcess(int processId);
        List<string> GetRunningUserProcessNames();
        List<SoftwareInfo> GetInstalledSoftware();
        List<StartupProgram> GetStartupPrograms();
        List<NetworkConnectionInfo> GetActiveNetworkConnections();
    }
}