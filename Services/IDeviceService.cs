using SecurityShield.Models;
using System.Collections.Generic;

namespace SecurityShield.Services
{
    public interface IDeviceService
    {
        event EventHandler DeviceListChanged;
        List<DeviceInfo> GetConnectedDevices();
        bool CheckDeviceSafety(DeviceInfo device);
        void EjectDevice(string deviceId);
        void OpenDeviceSettings(string deviceId);
    }
}