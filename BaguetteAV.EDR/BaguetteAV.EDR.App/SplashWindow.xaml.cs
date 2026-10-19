using System.Windows;
using System.Windows.Media.Animation;

namespace BaguetteAV.EDR.App;

public partial class SplashWindow : Window
{
    public SplashWindow()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            var fade = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(260));
            BeginAnimation(OpacityProperty, fade);
        };
        ContentRendered += (_, _) => WindowPlacement.CenterOnWorkArea(this, fit: false);
    }
}
