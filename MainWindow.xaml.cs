using System.Windows;

namespace SecurityShield
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            if (System.ComponentModel.DesignerProperties.GetIsInDesignMode(this))
                return;
            InitializeComponent();
        }
    }
}