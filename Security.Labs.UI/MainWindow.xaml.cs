﻿using Microsoft.Win32;
using Security.Labs.Algorithms;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;

namespace Security.Labs;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    public ObservableCollection<long> RandomNumbers { get; set; }
    private readonly BackgroundWorker backgroundWorker;
    private LehmerGenerator generator;
    private string selectedFilePathForMD5;

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

    #region Lehmer
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

    private void BtnCancel_Click(object sender, RoutedEventArgs e)
    {
        if (backgroundWorker.IsBusy)
        {
            backgroundWorker.CancelAsync();
        }
    }

    #region UIHelpers
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
            lblPeriod.Content = $"The period of the sequence is: {period} (First occurrence at index {firstPeriodOccurrence})";
        }
        else
        {
            lblPeriod.Content = "No period found within the specified count.";
        }
    }
    #endregion UIHelpers

    #endregion Lehmer

    #region MD5
    private void ComputeMD5ForTextButton_Click(object sender, RoutedEventArgs e)
    {
        var input = InputTextBox.Text;
        ResultTextBlock.Text = $"Hash: {MD5.Calculate(Encoding.UTF8.GetBytes(input))}";
    }

    private void SelectFileButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            selectedFilePathForMD5 = openFileDialog.FileName;
            SelectedFileTextBlock.Text = $"Selected file: {selectedFilePathForMD5}";
        }
    }

    private void ComputeMD5ForFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(selectedFilePathForMD5))
        {
            MessageBox.Show("Please select a file first.");
            return;
        }

        try
        {
            var fileBytes = File.ReadAllBytes(selectedFilePathForMD5);
            ResultTextBlock.Text = $"Hash: {MD5.Calculate(fileBytes)}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error reading file: {ex.Message}");
        }
    }

    private void InputTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ResultTextBlock.Text = string.Empty; selectedFilePathForMD5 = string.Empty; SelectedFileTextBlock.Text = string.Empty;
        var selectedInput = (ComboBoxItem)((ComboBox)sender).SelectedItem;
        if (selectedInput.Content.ToString() == "Text")
        {
            TextBoxPanel.Visibility = Visibility.Visible;
            FilePanel.Visibility = Visibility.Collapsed;
        }
        else if (selectedInput.Content.ToString() == "File")
        {
            TextBoxPanel.Visibility = Visibility.Collapsed;
            FilePanel.Visibility = Visibility.Visible;
        }
    }

    private void CheckFileIntegrityButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            var filePathToCompare = openFileDialog.FileName;
            var result = MD5.VerifyFileIntegrity(selectedFilePathForMD5, filePathToCompare);
            ResultTextBlock.Text = string.Empty;
            IntegrityResulTextBlock.Text = $"Check was {(result.IsCheckPassed ? "passed" : "not passed")}\n";
            IntegrityResulTextBlock.Text += $"Actual: {result.ActualResult}\nExpected: {result.ExpectedResult}";
        }
    }
    #endregion MD5

    #region RC5
    private void SelectFileToEncodeButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            Title = "Select file to encode"
        };

        if (openFileDialog.ShowDialog() == true)
        {
            SelectedFileToEncodeTextBlock.Text = openFileDialog.FileName;
            EncodeButton.IsEnabled = true;
        }
    }

    private void SaveFileToDecodingButton_Click(object sender, RoutedEventArgs e)
    {
        var saveFileDialog = new SaveFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
            Title = "Save decoded file as"
        };

        if (saveFileDialog.ShowDialog() == true)
        {
            SelectedFileToDecodingTextBlock.Text = saveFileDialog.FileName;
        }
    }


    private void EncodeButton_Click(object sender, RoutedEventArgs e)
    {
        const int KeyLength = 16;
        var rc5 = new RC5(32, 12, KeyLength);

        var fileToEncode = SelectedFileToEncodeTextBlock.Text;
        if (string.IsNullOrWhiteSpace(fileToEncode))
        {
            MessageBox.Show("Please select a file to encode!", "Attention", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var key = HelperMethods.GetHashedKey(Encoding.UTF8.GetBytes(KeyTextBox.Text), KeyLength);
       
        var destinationFile = GetEncodedFilePath(fileToEncode);

        try
        {
            rc5.EncodeFile(fileToEncode, key, destinationFile);
            MessageBox.Show($"Data is encoded in file:\n{destinationFile}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            DecodeButton.IsEnabled = true;
            SaveFileToDecodingButton.IsEnabled = true;
        }
        catch
        {
            MessageBox.Show("Error occured during encoding", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string GetEncodedFilePath(string fileToEncode)
    {
        var directoryPath = Path.GetDirectoryName(fileToEncode) ?? string.Empty;
        var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileToEncode);
        var fullPathWithoutExtension = Path.Combine(directoryPath, fileNameWithoutExtension);
        var destinationFile = fullPathWithoutExtension + "-encoded" + Path.GetExtension(fileToEncode);

        return destinationFile;
    }


    private void DecodeButton_Click(object sender, RoutedEventArgs e)
    {
        const int KeyLength = 16;
        var rc5 = new RC5(wordSize: 32, roundsCount: 12, keyLengthInBytes: KeyLength);
        var decodedPath = SelectedFileToDecodingTextBlock.Text;
        if (string.IsNullOrWhiteSpace(SelectedFileToDecodingTextBlock.Text))
        {
            MessageBox.Show("Please select a file to decode.");
            return;
        }

        var key = HelperMethods.GetHashedKey(Encoding.UTF8.GetBytes(KeyTextBoxConfirmation.Text), KeyLength);

        try
        {
            rc5.DecodeFile(GetEncodedFilePath(SelectedFileToEncodeTextBlock.Text), key, decodedPath);
            MessageBox.Show($"Data is decoded in file:\n{decodedPath}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch
        {
            MessageBox.Show("Key is not correct", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
       
    }
    #endregion

    private void AllowOnlyNumbersPreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
    {
        var regex = new Regex("[^0-9]+"); // Only allow digits
        e.Handled = regex.IsMatch(e.Text);
    }
}