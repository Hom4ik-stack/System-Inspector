using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;

namespace SecurityShield.Converters
{
    public class SeverityToColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var severity = value?.ToString()?.ToLower();
            return severity switch
            {
                "critical" => new SolidColorBrush(Colors.Red),
                "high" => new SolidColorBrush(Colors.OrangeRed),
                "medium" => new SolidColorBrush(Colors.Orange),
                "low" => new SolidColorBrush(Colors.YellowGreen),
                _ => new SolidColorBrush(Colors.Gray)
            };
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}