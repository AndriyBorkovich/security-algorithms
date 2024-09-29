using Security.Labs.Algorithms;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace Security.Labs;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public ObservableCollection<long> RandomNumbers { get; set; }
    private readonly BackgroundWorker backgroundWorker;
    private LehmerGenerator generator;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
        RandomNumbers = [];

        lstNumbers.ItemsSource = RandomNumbers;
        backgroundWorker = new BackgroundWorker
        {
            WorkerReportsProgress = true,
            WorkerSupportsCancellation = true
        };

        backgroundWorker.DoWork += BackgroundWorker_DoWork;
        backgroundWorker.ProgressChanged += BackgroundWorker_ProgressChanged;
        backgroundWorker.RunWorkerCompleted += BackgroundWorker_RunWorkerCompleted;

    }
    private void BackgroundWorker_DoWork(object? sender, DoWorkEventArgs e)
    {
        if (backgroundWorker.CancellationPending)
        {
            e.Cancel = true;
            return;
        }

        var randomNumbers = generator.GenerateSequence(
            out var period,
            out var firstPeriodOccurrence,
            progress => backgroundWorker.ReportProgress((int)progress));

        e.Result = new { RandomNumbers = randomNumbers, Period = period, FirstOccurrence = firstPeriodOccurrence };
    }

    private void BackgroundWorker_RunWorkerCompleted(object? sender, RunWorkerCompletedEventArgs e)
    {
        if (e.Cancelled)
        {
            MessageBox.Show("Generation was cancelled.", "Cancelled", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else if (e.Error != null)
        {
            MessageBox.Show($"Error: {e.Error.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        else
        {
            dynamic result = e.Result;
            List<long> numbers = new(result?.RandomNumbers);
            int? period = result?.Period;
            int firstPeriodOccurence = result?.FirstOccurrence ?? 0;
            Dispatcher.Invoke(() =>
            {
                OutputGeneratedDataToUi(numbers, period, firstPeriodOccurence);

                MessageBox.Show("Generation complete", "Completed", MessageBoxButton.OK, MessageBoxImage.Information);

                progressBar.Visibility = Visibility.Collapsed;
                btnCancel.IsEnabled = false;
            });
        }
    }

    private void BackgroundWorker_ProgressChanged(object? sender, ProgressChangedEventArgs e)
    {
        progressBar.Value = e.ProgressPercentage;
    }

    private void Generate_Click(object sender, RoutedEventArgs e)
    {
        RandomNumbers.Clear();

        lblPeriod.Content = "Period Information";

        if (!IsValidInput())
        {
            return;
        }

        if (!backgroundWorker.IsBusy)
        {
            generator = new LehmerGenerator(
               long.Parse(txtMultiplier.Text),
               long.Parse(txtIncrement.Text),
               long.Parse(txtModulus.Text),
               long.Parse(txtSeed.Text),
               int.Parse(txtCount.Text),
               chkOutputToFile.IsChecked.HasValue && chkOutputToFile.IsChecked.Value);

            progressBar.Value = 0;
            progressBar.Visibility = Visibility.Visible;
            btnCancel.IsEnabled = true;
            backgroundWorker.RunWorkerAsync();
        }
    }

    private void ComputeButton_Click(object sender, RoutedEventArgs e)
    {
        var input = InputTextBox.Text;
        var hash = MD5.ComputeHashForString(input);
        ResultTextBlock.Text = $"Hash: {hash}";
    }

    private bool IsValidInput()
    {
        // Create a mapping of input fields with corresponding error messages
        var inputFields = new Dictionary<TextBox, string>
        {
            { txtModulus, "Modulus (m)" },
            { txtMultiplier, "Multiplier (a)" },
            { txtIncrement, "Increment (c)" },
            { txtSeed, "Seed (X0)" },
            { txtCount, "Count" }
        };

        foreach (var field in inputFields)
        {
            if (string.IsNullOrWhiteSpace(field.Key.Text) || !IsNumeric(field.Key.Text, field.Key == txtCount ? typeof(int) : typeof(long)))
            {
                ShowValidationError(field.Value);
                field.Key.Focus();
                return false;
            }
        }

        return true;

        bool IsNumeric(string input, Type type)
        {
            if (type == typeof(int))
                return int.TryParse(input, out _);
            else if (type == typeof(long))
                return long.TryParse(input, out _);

            return false;
        }

        void ShowValidationError(string fieldName)
        {
            MessageBox.Show($"Please enter a valid {fieldName}.", "Input Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OutputGeneratedDataToUi(List<long> randomNumbers, int? period, int firstPeriodOccurrence)
    {
        RandomNumbers.Clear();

        foreach (var number in randomNumbers)
        {
            RandomNumbers.Add(number);
        }

        if (period.HasValue)
        {
            HighlightPeriodIndices(period.Value, firstPeriodOccurrence);

            lblPeriod.Content = $"The period of the sequence is: {period} (First occurrence at index {firstPeriodOccurrence})";
        }
        else
        {
            lblPeriod.Content = "No period found within the specified count.";
        }
    }

    private void HighlightPeriodIndices(int period, int firstOccurrence)
    {
        for (int i = firstOccurrence; i < RandomNumbers.Count; i += period)
        {
            if (lstNumbers.ItemContainerGenerator.ContainerFromIndex(i) is ListBoxItem item)
            {
                item.Background = Brushes.LightGreen;
            }
        }
    }

    private void AllowOnlyNumbersPreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
    {
        var regex = new Regex("[^0-9]+"); // Only allow digits
        e.Handled = regex.IsMatch(e.Text);
    }

    private void BtnCancel_Click(object sender, RoutedEventArgs e)
    {
        if (backgroundWorker.IsBusy)
        {
            backgroundWorker.CancelAsync();
        }
    }
}