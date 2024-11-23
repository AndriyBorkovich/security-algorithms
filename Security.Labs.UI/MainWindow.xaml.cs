using Microsoft.Win32;
using Security.Labs.Algorithms;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using MD5 = Security.Labs.Algorithms.MD5;
using RSA = Security.Labs.Algorithms.RSA;
using DSA = Security.Labs.Algorithms.DSA;

namespace Security.Labs;

/// <summary>
/// Interaction logic for MainWindow.xaml
/// </summary>
public partial class MainWindow : Window
{
    #region LCG_Fields
    public ObservableCollection<long> RandomNumbers { get; set; }
    private readonly BackgroundWorker backgroundWorker;
    private LehmerGenerator generator;
    #endregion
    
    #region MD5_Fields
    private string _selectedFilePathForMD5;
    #endregion

    #region RC5_Fields
    private string _enteredKeyFilePath;
    private string _reenteredKeyFilePath;
    #endregion

    #region RSA_Fields
    private string _publicKeyPath;
    private string _privateKeyPath;
    private string _encryptFilePath;
    private string _decryptFilePath;
    private string _encryptedFilePath;
    private string _decryptedFilePath;
    #endregion

    #region DSA_Fields
    private readonly DSA _dsa = new();
    private string _selectedFilePath;
    private string _signature;
    #endregion

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
            _selectedFilePathForMD5 = openFileDialog.FileName;
            SelectedFileTextBlock.Text = $"Selected file: {_selectedFilePathForMD5}";
        }
    }

    private void ComputeMD5ForFileButton_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_selectedFilePathForMD5))
        {
            MessageBox.Show("Please select a file first.");
            return;
        }

        try
        {
            var fileBytes = File.ReadAllBytes(_selectedFilePathForMD5);
            ResultTextBlock.Text = $"Hash: {MD5.Calculate(fileBytes)}";
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error reading file: {ex.Message}");
        }
    }

    private void InputTypeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        ResultTextBlock.Text = string.Empty; _selectedFilePathForMD5 = string.Empty; SelectedFileTextBlock.Text = string.Empty;
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
            var result = MD5.VerifyFileIntegrity(_selectedFilePathForMD5, filePathToCompare);
            ResultTextBlock.Text = string.Empty;
            IntegrityResulTextBlock.Text = $"Check was {(result.IsCheckPassed ? "passed" : "not passed")}\n";
            IntegrityResulTextBlock.Text += $"Actual: {result.ActualResult}\nExpected: {result.ExpectedResult}";
        }
    }
    #endregion MD5

    #region RC5

    private void KeyInputMethodComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (KeyTextBox != null && LoadKeyFromFileButton != null)
        {
            if (KeyInputMethodComboBox.SelectedIndex == 0) // "Enter manually"
            {
                KeyTextBox.Visibility = Visibility.Visible;
                LoadKeyFromFileButton.Visibility = Visibility.Collapsed;
            }
            else if (KeyInputMethodComboBox.SelectedIndex == 1) // "Load from file"
            {
                KeyTextBox.Visibility = Visibility.Collapsed;
                LoadKeyFromFileButton.Visibility = Visibility.Visible;
            }
        }
    }

    private void LoadKeyFromFileButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
        };

        if (openFileDialog.ShowDialog() == true)
        {
            _enteredKeyFilePath = openFileDialog.FileName;

            MessageBox.Show("Key loaded from file successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void ReenterKeyInputMethodComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (KeyTextBoxConfirmation != null && LoadReenterKeyFromFileButton != null)
        {
            if (ReenterKeyInputMethodComboBox.SelectedIndex == 0) // "Enter manually"
            {
                KeyTextBoxConfirmation.Visibility = Visibility.Visible;
                LoadReenterKeyFromFileButton.Visibility = Visibility.Collapsed;
            }
            else if (ReenterKeyInputMethodComboBox.SelectedIndex == 1) // "Load from file"
            {
                KeyTextBoxConfirmation.Visibility = Visibility.Collapsed;
                LoadReenterKeyFromFileButton.Visibility = Visibility.Visible;
            }
        }
    }

    private void LoadReenterKeyFromFileButton_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog
        {
            Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*"
        };

        if (openFileDialog.ShowDialog() == true)
        {
            _reenteredKeyFilePath = openFileDialog.FileName;
            MessageBox.Show("Re-entered key loaded from file successfully.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

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

        var key = KeyInputMethodComboBox.SelectedIndex == 0 ? HelperMethods.GetHashedKey(Encoding.UTF8.GetBytes(KeyTextBox.Text), KeyLength) : File.ReadAllBytes(_enteredKeyFilePath);
       
        var destinationFile = GetProcessedFilePath(fileToEncode);

        try
        {
            var elapsedTime = rc5.EncodeFileBenchmark(fileToEncode, key, destinationFile);
            MessageBox.Show($"Data is encoded in file:\n{destinationFile}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            DecodeButton.IsEnabled = true;
            SaveFileToDecodingButton.IsEnabled = true;
            EncodingTimeTextBlock.Text = $"Elapsed: {elapsedTime} ms";
        }
        catch
        {
            MessageBox.Show("Error occured during encoding", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string GetProcessedFilePath(string fileToProcess)
    {
        var directoryPath = Path.GetDirectoryName(fileToProcess) ?? string.Empty;
        var fileNameWithoutExtension = Path.GetFileNameWithoutExtension(fileToProcess);
        var fullPathWithoutExtension = Path.Combine(directoryPath, fileNameWithoutExtension);
        var destinationFile = fullPathWithoutExtension + "-encoded" + Path.GetExtension(fileToProcess);

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

        var key = ReenterKeyInputMethodComboBox.SelectedIndex == 0 ? HelperMethods.GetHashedKey(Encoding.UTF8.GetBytes(KeyTextBoxConfirmation.Text), KeyLength) : File.ReadAllBytes(_reenteredKeyFilePath) ;

        try
        {
            var elapsedTime = rc5.DecryptFileBenchmark(GetProcessedFilePath(SelectedFileToEncodeTextBlock.Text), key, decodedPath);
            MessageBox.Show($"Data is decoded in file:\n{decodedPath}", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
            DecodingTimeTextBlock.Text = $"Elapsed: {elapsedTime} ms";
        }
        catch
        {
            MessageBox.Show("Key is not correct", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
       
    }
    #endregion

    #region RSA
    private void GenerateKeyPair_Click(object sender, RoutedEventArgs e)
    {
        var saveDialog = new SaveFileDialog { Filter = "Key files (*.key)|*.key" };
        if (saveDialog.ShowDialog() == true)
        {
            RSA.GeneteKeyPair(saveDialog.FileName + "_public.key", saveDialog.FileName + "_private.key");
            MessageBox.Show("Key pair generated successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void SelectPublicKey_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog { Filter = "Public Key (*.key)|*.key" };
        if (openDialog.ShowDialog() == true)
        {
            _publicKeyPath = openDialog.FileName;
        }
    }

    private void SelectPrivateKey_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog { Filter = "Private Key (*.key)|*.key" };
        if (openDialog.ShowDialog() == true)
        {
            _privateKeyPath = openDialog.FileName;
        }
    }

    private void SelectEncryptFile_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog { Filter = "All Files (*.*)|*.*" };
        if (openDialog.ShowDialog() == true)
        {
            _encryptFilePath = openDialog.FileName;
        }
    }

    private void SelectEncryptedFilePath_Click(object sender, RoutedEventArgs e)
    {
        var saveDialog = new SaveFileDialog { Filter = "Binary Files (*.bin)|*.bin" };
        if (saveDialog.ShowDialog() == true)
        {
            _encryptedFilePath = saveDialog.FileName;
        }
    }

    private void EncryptFile_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(_encryptFilePath) || !File.Exists(_publicKeyPath) || string.IsNullOrEmpty(_encryptedFilePath))
        {
            MessageBox.Show("Please select a file, public key, and output path for encryption.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        try
        {
            var encryptionTime = RSA.EncryptFile(_encryptFilePath, _publicKeyPath, _encryptedFilePath);
            EncryptionTimeTextBox.Text = encryptionTime.ToString();
            MessageBox.Show("File encrypted successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error during ecryption: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SelectDecryptFile_Click(object sender, RoutedEventArgs e)
    {
        var openDialog = new OpenFileDialog { Filter = "Binary Files (*.bin)|*.bin" };
        if (openDialog.ShowDialog() == true)
        {
            _decryptFilePath = openDialog.FileName;
        }
    }

    private void SelectDecryptedFilePath_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_decryptFilePath))
        {
            MessageBox.Show("Please select an encrypted file first to determine the original format.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        var originalExtension = Path.GetExtension(_decryptFilePath.Replace(".bin", ""));
        var saveDialog = new SaveFileDialog { Filter = $"Original Format (*{originalExtension})|*{originalExtension}" };
        if (saveDialog.ShowDialog() == true)
        {
            _decryptedFilePath = saveDialog.FileName;
        }
    }

    private void DecryptFile_Click(object sender, RoutedEventArgs e)
    {
        if (!File.Exists(_decryptFilePath) || !File.Exists(_privateKeyPath) || string.IsNullOrEmpty(_decryptedFilePath))
        {
            MessageBox.Show("Please select an encrypted file, private key, and output path for decryption.", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
            return;
        }

        try
        {
            var decryptionTime = RSA.DecryptFile(_decryptFilePath, _privateKeyPath, _decryptedFilePath);
            DecryptionTimeTextBox.Text = decryptionTime.ToString();
            MessageBox.Show("File decrypted successfully!", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error during decryption: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        
    }
    #endregion RSA

    #region DSA

    private void SelectPublicKeyPath_Click(object sender, RoutedEventArgs e)
    {
        var saveFileDialog = new SaveFileDialog
        {
            Filter = "Keys (*.key)|*.key",
            Title = "Choose save location for public key"
        };
        if (saveFileDialog.ShowDialog() == true)
        {
            PublicKeyPathTextBox.Text = saveFileDialog.FileName;
        }
    }

    private void SelectPrivateKeyPath_Click(object sender, RoutedEventArgs e)
    {
        var saveFileDialog = new SaveFileDialog
        {
            Filter = "Keys (*.key)|*.key",
            Title = "Choose save location for private key"
        };
        if (saveFileDialog.ShowDialog() == true)
        {
            PrivateKeyPathTextBox.Text = saveFileDialog.FileName;
        }
    }

    private void ExportKeys_Click(object sender, RoutedEventArgs e)
    {
        var publicKeyPath = PublicKeyPathTextBox.Text;
        var privateKeyPath = PrivateKeyPathTextBox.Text;

        if (string.IsNullOrWhiteSpace(publicKeyPath) || string.IsNullOrWhiteSpace(privateKeyPath))
        {
            MessageBox.Show("Please choose paths for keys export!", "Attention", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            _dsa.ExportKeys(publicKeyPath, privateKeyPath);
            MessageBox.Show("Keys were exported successfully");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error during import:{ex.Message}!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void SelectImportPublicKeyPath_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog
        {
            Filter = "Keys (*.key)|*.key",
            Title = "Select public key to import"
        };
        if (openFileDialog.ShowDialog() == true)
        {
            ImportPublicKeyPathTextBox.Text = openFileDialog.FileName;
        }
    }

    private void SelectImportPrivateKeyPath_Click(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog
        {
            Filter = "Keys (*.key)|*.key",
            Title = "Select private key to import"
        };
        if (openFileDialog.ShowDialog() == true)
        {
            ImportPrivateKeyPathTextBox.Text = openFileDialog.FileName;
        }
    }

    private void ImportKeys_Click(object sender, RoutedEventArgs e)
    {
        var publicKeyPath = ImportPublicKeyPathTextBox.Text;
        var privateKeyPath = ImportPrivateKeyPathTextBox.Text;

        if (string.IsNullOrWhiteSpace(publicKeyPath) || string.IsNullOrWhiteSpace(privateKeyPath))
        {
            MessageBox.Show("Please choose paths for keys import!", "Attention", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            _dsa.ImportKeys(publicKeyPath, privateKeyPath);
            MessageBox.Show("Keys were imported successfully!");
        }
        catch (Exception ex)
        {
            MessageBox.Show($"Error during import:{ex.Message}!", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
       
    }

    private void OnInputTypeChanged(object sender, RoutedEventArgs e)
    {
        if (DsaInputTypeComboBox.SelectedIndex < 0) return;

        if (DsaInputText is not null && DsaSelectFileButton is not null)
        {
            if (DsaInputTypeComboBox.SelectedIndex == 0)
            {
                DsaInputText.Visibility = Visibility.Visible;
                DsaSelectFileButton.Visibility = Visibility.Collapsed;
            }
            else if (DsaInputTypeComboBox.SelectedIndex == 1)
            {
                DsaInputText.Visibility = Visibility.Collapsed;
                DsaSelectFileButton.Visibility = Visibility.Visible;
            }
        }
    }

    private void OnSign(object sender, RoutedEventArgs e)
    {
        if (DsaInputTypeComboBox.SelectedIndex == 0)
        {
            var text = DsaInputText.Text;
            _signature = _dsa.SignData(text);
        }
        else if (DsaInputTypeComboBox.SelectedIndex == 1 && !string.IsNullOrEmpty(_selectedFilePath))
        {
            try
            {
                var fileData = File.ReadAllText(_selectedFilePath);
                _signature = _dsa.SignData(fileData);
            }
            catch (Exception ex)
            {

            }
        }

        SignatureDisplay.Text = $"Signature: {_signature}";
    }

    private void OnSaveSignature(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_signature))
        {
            var saveFileDialog = new SaveFileDialog { FileName = "signature.txt" };
            if (saveFileDialog.ShowDialog() == true)
            {
                File.WriteAllText(saveFileDialog.FileName, _signature);
            }
        }
        else
        {
            MessageBox.Show("Signature is empty", "Attention", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void OnSelectFileToSign(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            _selectedFilePath = openFileDialog.FileName;
        }
    }

    private void OnSelectFileToVerify(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            _selectedFilePath = openFileDialog.FileName;
        }
    }

    private void OnSelectSignatureFile(object sender, RoutedEventArgs e)
    {
        var openFileDialog = new OpenFileDialog();
        if (openFileDialog.ShowDialog() == true)
        {
            var signaturePath = openFileDialog.FileName;
            _signature = File.ReadAllText(signaturePath);
        }
    }

    private void OnVerifyFileSignature(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrEmpty(_selectedFilePath) && !string.IsNullOrEmpty(_signature))
        {
            var data = File.ReadAllText(_selectedFilePath);
            var result = _dsa.VerifySignature(data, _signature);
            VerificationResultText.Text = result ? "Signature is valid." : "Signature is invalid.";
        }
        else
        {
            MessageBox.Show("Please select a file and its signature for verification.");
        }
    }
    #endregion

    private void AllowOnlyNumbersPreviewTextInput(object sender, TextCompositionEventArgs e)
    {
        var regex = new Regex("[^0-9]+"); // Only allow digits
        e.Handled = regex.IsMatch(e.Text);
    }
}