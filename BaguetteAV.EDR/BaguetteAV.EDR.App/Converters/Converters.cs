using BaguetteAV.EDR.Core.Models;
using System.Globalization;
using System.Windows;
using System.Windows.Data;
using WpfBinding = System.Windows.Data.Binding;
using MediaBrush = System.Windows.Media.Brush;
using MediaColor = System.Windows.Media.Color;
using MediaSolidColorBrush = System.Windows.Media.SolidColorBrush;

namespace BaguetteAV.EDR.App.Converters;

public sealed class SeverityBrushConverter : IValueConverter
{
    private static readonly MediaBrush Critical = new MediaSolidColorBrush(MediaColor.FromRgb(0xE5, 0x48, 0x4D));
    private static readonly MediaBrush High = new MediaSolidColorBrush(MediaColor.FromRgb(0xF2, 0x6B, 0x3B));
    private static readonly MediaBrush Medium = new MediaSolidColorBrush(MediaColor.FromRgb(0xE8, 0xA3, 0x17));
    private static readonly MediaBrush Low = new MediaSolidColorBrush(MediaColor.FromRgb(0x3B, 0x82, 0xF6));

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var text = value is DetectionRecord detection ? detection.SeverityText : value?.ToString();
        return text switch
        {
            "严重" => Critical,
            "高危" => High,
            "中危" => Medium,
            _ => Low
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => WpfBinding.DoNothing;
}

public sealed class SeverityBackgroundConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var text = value is DetectionRecord detection ? detection.SeverityText : value?.ToString();
        return text switch
        {
            "严重" => new MediaSolidColorBrush(MediaColor.FromRgb(0xFD, 0xEB, 0xEC)),
            "高危" => new MediaSolidColorBrush(MediaColor.FromRgb(0xFE, 0xF0, 0xE9)),
            "中危" => new MediaSolidColorBrush(MediaColor.FromRgb(0xFF, 0xF7, 0xE2)),
            _ => new MediaSolidColorBrush(MediaColor.FromRgb(0xE9, 0xF1, 0xFE))
        };
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => WpfBinding.DoNothing;
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) => !(value is true);
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => !(value is true);
}

public sealed class BoolToBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? new MediaSolidColorBrush(MediaColor.FromRgb(0x19, 0xA9, 0x74))
                      : new MediaSolidColorBrush(MediaColor.FromRgb(0xE5, 0x48, 0x4D));
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => WpfBinding.DoNothing;
}

public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is null ? Visibility.Collapsed : Visibility.Visible;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => WpfBinding.DoNothing;
}

public sealed class InverseNullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is null ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => WpfBinding.DoNothing;
}

public sealed class CountToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int count && count > 0 ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => WpfBinding.DoNothing;
}

public sealed class ZeroToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is int count && count == 0 ? Visibility.Visible : Visibility.Collapsed;
    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) => WpfBinding.DoNothing;
}
