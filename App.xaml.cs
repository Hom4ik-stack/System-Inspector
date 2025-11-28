using System.Windows;
using SecurityShield.Services;
using SecurityShield.ViewModels;

namespace SecurityShield
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            // Создаем сервисы
            var systemInfoService = new SystemInfoService();
            var driverService = new DriverService();
            var deviceService = new DeviceService();
            var securityService = new SecurityService();
            var reportService = new ReportService();

            // Создаем главную ViewModel
            var mainViewModel = new MainViewModel(
                systemInfoService,
                driverService,
                deviceService,
                securityService,
                reportService);

            // Создаем главное окно
            var mainWindow = new MainWindow();
            mainWindow.DataContext = mainViewModel;
            mainWindow.Show();
        }
    }
}