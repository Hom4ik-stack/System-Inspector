using CommunityToolkit.Mvvm.ComponentModel;
using LiveCharts;
using LiveCharts.Wpf;
using System;

namespace SecurityShield.Models
{
    public partial class DriveInfoModel : ObservableObject
    {
        [ObservableProperty]
        private string _name = string.Empty;

        [ObservableProperty]
        private long _totalSpace;

        [ObservableProperty]
        private long _freeSpace;

        [ObservableProperty]
        private string _driveType = string.Empty;

        [ObservableProperty]
        private string _driveFormat = string.Empty;

        // Вычисляемое свойство для использованного места (в байтах)
        public long UsedSpace => TotalSpace - FreeSpace;

        // Вычисляемое свойство для процента использования
        public double UsedPercentage => TotalSpace == 0 ? 0 : (1 - (double)FreeSpace / TotalSpace) * 100;

        // Вычисляемое свойство для свободного процента
        public double FreePercentage => TotalSpace == 0 ? 0 : ((double)FreeSpace / TotalSpace) * 100;

        // Форматированные свойства для отображения
        public string TotalSpaceFormatted => TotalSpace > 0 ? $"{(TotalSpace / 1024.0 / 1024.0 / 1024.0):F2} GB" : "N/A";
        public string FreeSpaceFormatted => FreeSpace > 0 ? $"{(FreeSpace / 1024.0 / 1024.0 / 1024.0):F2} GB" : "N/A";
        public string UsedSpaceFormatted => UsedSpace > 0 ? $"{(UsedSpace / 1024.0 / 1024.0 / 1024.0):F2} GB" : "N/A";

        // Функция для подписей на диаграмме
        public Func<ChartPoint, string> PointLabel => point => $"{point.Y:F1} GB";

        private SeriesCollection? _driveSeries;

        public SeriesCollection? DriveSeries
        {
            get => _driveSeries;
            set => SetProperty(ref _driveSeries, value);
        }

        public void UpdateDriveSeries()
        {
            if (TotalSpace == 0) return;

            try
            {
                var usedGb = (TotalSpace - FreeSpace) / 1024.0 / 1024.0 / 1024.0;
                var freeGb = FreeSpace / 1024.0 / 1024.0 / 1024.0;

                DriveSeries = new SeriesCollection
                {
                    new PieSeries
                    {
                        Title = "Использовано",
                        Values = new ChartValues<double> { usedGb },
                        DataLabels = true,
                        LabelPoint = PointLabel
                    },
                    new PieSeries
                    {
                        Title = "Свободно",
                        Values = new ChartValues<double> { freeGb },
                        DataLabels = true,
                        LabelPoint = PointLabel
                    }
                };
            }
            catch (Exception ex)
            {
                // Логируем ошибку, но не падаем
                System.Diagnostics.Debug.WriteLine($"Ошибка обновления диаграммы: {ex.Message}");
                DriveSeries = null;
            }
        }

        // Метод для обновления диаграммы при изменении данных
        protected override void OnPropertyChanged(System.ComponentModel.PropertyChangedEventArgs e)
        {
            base.OnPropertyChanged(e);

            if (e.PropertyName == nameof(TotalSpace) || e.PropertyName == nameof(FreeSpace))
            {
                UpdateDriveSeries();
            }
        }
    }
}