using System;
using System.Globalization;
using System.Windows;
using System.Windows.Data;

namespace SecurityShield.Converters 
{
    public class ContainsStringVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            var text = value as string;
            var substring = parameter as string;

            if (text == null || substring == null)
                return Visibility.Collapsed;

            if (text.IndexOf(substring, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return Visibility.Visible;
            }
            return Visibility.Collapsed;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}