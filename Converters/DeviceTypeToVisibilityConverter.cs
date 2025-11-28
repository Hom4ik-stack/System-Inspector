using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace SecurityShield.Converters
{
    public class DeviceTypeToVisibilityConverter : IValueConverter
    {
        public static DeviceTypeToVisibilityConverter Instance { get; } = new DeviceTypeToVisibilityConverter();

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is string deviceType)
            {
                return deviceType.ToLower() switch
                {
                    "usb" => Visibility.Visible,
                    "disk" => Visibility.Visible,
                    _ => Visibility.Collapsed
                };
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}