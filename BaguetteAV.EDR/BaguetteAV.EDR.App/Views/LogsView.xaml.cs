using System.Collections.Specialized;

namespace BaguetteAV.EDR.App.Views;

public partial class LogsView : System.Windows.Controls.UserControl
{
    private INotifyCollectionChanged? _observed;

    public LogsView()
    {
        InitializeComponent();
        DataContextChanged += (_, _) => Rebind();
        Unloaded += (_, _) => Rebind();
    }

    private void Rebind()
    {
        if (_observed is not null) _observed.CollectionChanged -= OnCollectionChanged;
        _observed = LogList.ItemsSource as INotifyCollectionChanged;
        if (_observed is not null) _observed.CollectionChanged += OnCollectionChanged;
    }

    private void OnCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (LogList.Items.Count > 0)
            LogList.ScrollIntoView(LogList.Items[LogList.Items.Count - 1]);
    }
}
