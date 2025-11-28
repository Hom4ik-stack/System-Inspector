using SecurityShield.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace SecurityShield.Services
{
    public interface IDriverService
    {
        List<DriverInfo> GetInstalledDrivers();
        List<DriverInfo> CheckOutdatedDrivers();
   
     
    }
}