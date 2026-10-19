using BaguetteAV.EDR.App.ViewModels;
using System.Windows;

namespace BaguetteAV.EDR.App;

public partial class MainWindow : Window
{
    public MainWindow(MainViewModel viewModel)
    {
        InitializeComponent();
        DataContext = viewModel;
        StateChanged += (_, _) => ApplyWindowState();
        ContentRendered += (_, _) => WindowPlacement.CenterOnWorkArea(this, fit: true);
    }

    private void ApplyWindowState()
    {
        if (WindowState == WindowState.Maximized)
        {
            RootBorder.Margin = new Thickness(7);
            MaxButton.Content = "\uE923";
        }
        else
        {
            RootBorder.Margin = new Thickness(0);
            MaxButton.Content = "\uE922";
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void Maximize_Click(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
