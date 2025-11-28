using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Reflection;
using System.Windows;
using System.Windows.Data;

namespace SecurityShield.Converters
{
    public class EnumToDescriptionConverter : IValueConverter
    {
        public static EnumToDescriptionConverter Instance { get; } = new EnumToDescriptionConverter();

        private readonly Dictionary<Enum, string> _descriptionCache = new Dictionary<Enum, string>();

        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null)
                return DependencyProperty.UnsetValue;

            if (value is Enum enumValue)
            {
                if (!_descriptionCache.TryGetValue(enumValue, out string description))
                {
                    description = GetEnumDescription(enumValue);
                    _descriptionCache[enumValue] = description;
                }
                return description;
            }

            return value.ToString();
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value;
        }

        private string GetEnumDescription(Enum value)
        {
            FieldInfo fieldInfo = value.GetType().GetField(value.ToString());

            if (fieldInfo == null)
                return value.ToString();

            var attribute = fieldInfo.GetCustomAttribute<DescriptionAttribute>();
            return attribute?.Description ?? value.ToString();
        }
    }
}