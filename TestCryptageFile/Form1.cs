using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Runtime.ConstrainedExecution;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TestCryptageFile
{
    public partial class Form1 : Form
    {
        // Declare CspParmeters and RsaCryptoServiceProvider
        // objects with global scope of your Form class.
        RSACryptoServiceProvider _rsa;

        // Path variables for source, encryption, and
        // decryption folders. Must end with a backslash.
        const string EncrFolder = @"c:\test_encrypt\Encrypt\";
        const string DecrFolder = @"c:\test_encrypt\Decrypt\";
        const string SrcFolder = @"c:\test_encrypt\docs\";

        // Public key file
        const string PubKeyFile = @"c:\encrypt\rsaPublicKey.txt";

        // Key container name for
        // private/public key value pair.
        const string KeyName = "Key01";
        const int KeySize = 2048;

        public Form1()
        {
            InitializeComponent();
        }

        private void buttonCreateAsmKeys_Click(object sender, EventArgs e)
        {
            // Stores a key pair in the key container.
            var parameters = new CspParameters
            {
                KeyContainerName = KeyName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            _rsa = new RSACryptoServiceProvider(KeySize, parameters)
            {
                PersistKeyInCsp = true
            };

            label1.Text = _rsa.PublicOnly
                ? $"Key: {parameters.KeyContainerName} - Public Only"
                : $"Key: {parameters.KeyContainerName} - Full Key Pair";

            GrantUser();
        }

        private void GrantUser()
        {
            var lUserName = "User";

            var lRuntime = System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();

            var lFile = Path.Combine(lRuntime, "aspnet_regiis.exe");

            if (File.Exists(lFile))
            {
                //var psi = new ProcessStartInfo(lFile)
                //{
                //    Arguments = string.Format(@"-pa ""{0}"" ""{1}""", KeyName, lUserName),
                //    UseShellExecute = false,
                //    CreateNoWindow = true
                //};

                Process process = new Process();
                // Configure the process using the StartInfo properties.
                process.StartInfo.FileName = lFile;
                process.StartInfo.Arguments = string.Format(@"-pa ""{0}"" ""{1}""", KeyName, lUserName);
                process.StartInfo.WindowStyle = ProcessWindowStyle.Normal;

                //todo comment catcher les erreurs ?

                process.Start();
                process.WaitForExit();// Waits here for the process to exit.
            }
            else
            {
                throw new FileNotFoundException("impossible de localiser aspnet_regiis");
            }



            // input: "X509Certificate2 cert"
        }

        private void buttonEncryptFile_Click(object sender, EventArgs e)
        {
            if (_rsa is null)
            {
                MessageBox.Show("Key not set.");
            }
            else
            {
                // Display a dialog box to select a file to encrypt.
                _encryptOpenFileDialog.InitialDirectory = SrcFolder;
                if (_encryptOpenFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string fName = _encryptOpenFileDialog.FileName;
                    if (fName != null)
                    {
                        // Pass the file name without the path.
                        EncryptFile(new FileInfo(fName));
                    }
                }
            }
        }

        private void EncryptFile(FileInfo file)
        {
            // Create instance of Aes for
            // symmetric encryption of the data.
            Aes aes = Aes.Create();
            ICryptoTransform transform = aes.CreateEncryptor();

            // Use RSACryptoServiceProvider to
            // encrypt the AES key.
            // rsa is previously instantiated:
            //    rsa = new RSACryptoServiceProvider(cspp);
            byte[] keyEncrypted = _rsa.Encrypt(aes.Key, false);

            // Create byte arrays to contain
            // the length values of the key and IV.
            int lKey = keyEncrypted.Length;
            byte[] LenK = BitConverter.GetBytes(lKey);
            int lIV = aes.IV.Length;
            byte[] LenIV = BitConverter.GetBytes(lIV);

            // Write the following to the FileStream
            // for the encrypted file (outFs):
            // - length of the key
            // - length of the IV
            // - ecrypted key
            // - the IV
            // - the encrypted cipher content

            // Change the file's extension to ".enc"
            string outFile =
                Path.Combine(EncrFolder, Path.ChangeExtension(file.Name, ".enc"));

            using (var outFs = new FileStream(outFile, FileMode.Create))
            {
                outFs.Write(LenK, 0, 4);
                outFs.Write(LenIV, 0, 4);
                outFs.Write(keyEncrypted, 0, lKey);
                outFs.Write(aes.IV, 0, lIV);

                // Now write the cipher text using
                // a CryptoStream for encrypting.
                using (var outStreamEncrypted =
                    new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                {
                    // By encrypting a chunk at
                    // a time, you can save memory
                    // and accommodate large files.
                    int count = 0;
                    int offset = 0;

                    // blockSizeBytes can be any arbitrary size.
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];
                    int bytesRead = 0;

                    using (var inFs = new FileStream(file.FullName, FileMode.Open))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamEncrypted.Write(data, 0, count);
                            bytesRead += blockSizeBytes;
                        } while (count > 0);
                    }
                    outStreamEncrypted.FlushFinalBlock();
                }
            }
        }

        private void buttonDecryptFile_Click(object sender, EventArgs e)
        {
            if (_rsa is null)
            {
                MessageBox.Show("Key not set.");
            }
            else
            {
                // Display a dialog box to select the encrypted file.
                _decryptOpenFileDialog.InitialDirectory = EncrFolder;
                if (_decryptOpenFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string fName = _decryptOpenFileDialog.FileName;
                    if (fName != null)
                    {
                        DecryptFile(new FileInfo(fName));
                    }
                }
            }
        }

        private void DecryptFile(FileInfo file)
        {
            // Create instance of Aes for
            // symmetric decryption of the data.
            Aes aes = Aes.Create();

            // Create byte arrays to get the length of
            // the encrypted key and IV.
            // These values were stored as 4 bytes each
            // at the beginning of the encrypted package.
            byte[] LenK = new byte[4];
            byte[] LenIV = new byte[4];

            // Construct the file name for the decrypted file.
            string outFile =
                Path.ChangeExtension(file.FullName.Replace("Encrypt", "Decrypt"), ".txt");

            // Use FileStream objects to read the encrypted
            // file (inFs) and save the decrypted file (outFs).
            using (var inFs = new FileStream(file.FullName, FileMode.Open))
            {
                inFs.Seek(0, SeekOrigin.Begin);
                inFs.Read(LenK, 0, 3);
                inFs.Seek(4, SeekOrigin.Begin);
                inFs.Read(LenIV, 0, 3);

                // Convert the lengths to integer values.
                int lenK = BitConverter.ToInt32(LenK, 0);
                int lenIV = BitConverter.ToInt32(LenIV, 0);

                // Determine the start postition of
                // the ciphter text (startC)
                // and its length(lenC).
                int startC = lenK + lenIV + 8;
                int lenC = (int)inFs.Length - startC;

                // Create the byte arrays for
                // the encrypted Aes key,
                // the IV, and the cipher text.
                byte[] KeyEncrypted = new byte[lenK];
                byte[] IV = new byte[lenIV];

                // Extract the key and IV
                // starting from index 8
                // after the length values.
                inFs.Seek(8, SeekOrigin.Begin);
                inFs.Read(KeyEncrypted, 0, lenK);
                inFs.Seek(8 + lenK, SeekOrigin.Begin);
                inFs.Read(IV, 0, lenIV);

                Directory.CreateDirectory(DecrFolder);
                // Use RSACryptoServiceProvider
                // to decrypt the AES key.
                byte[] KeyDecrypted = _rsa.Decrypt(KeyEncrypted, false);

                // Decrypt the key.
                ICryptoTransform transform = aes.CreateDecryptor(KeyDecrypted, IV);

                // Decrypt the cipher text from
                // from the FileSteam of the encrypted
                // file (inFs) into the FileStream
                // for the decrypted file (outFs).
                using (var outFs = new FileStream(outFile, FileMode.Create))
                {
                    int count = 0;
                    int offset = 0;

                    // blockSizeBytes can be any arbitrary size.
                    int blockSizeBytes = aes.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];

                    // By decrypting a chunk a time,
                    // you can save memory and
                    // accommodate large files.

                    // Start at the beginning
                    // of the cipher text.
                    inFs.Seek(startC, SeekOrigin.Begin);
                    using (var outStreamDecrypted =
                        new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        do
                        {
                            count = inFs.Read(data, 0, blockSizeBytes);
                            offset += count;
                            outStreamDecrypted.Write(data, 0, count);
                        } while (count > 0);

                        outStreamDecrypted.FlushFinalBlock();
                    }
                }
            }
        }

        private void buttonExportPublicKey_Click(object sender, EventArgs e)
        {
            // Save the public key created by the RSA
            // to a file. Caution, persisting the
            // key to a file is a security risk.
            Directory.CreateDirectory(EncrFolder);
            using (var sw = new StreamWriter(PubKeyFile, false))
            {
                sw.Write(_rsa.ToXmlString(false));
            }
        }

        private void buttonImportPublicKey_Click(object sender, EventArgs e)
        {
            using (var sr = new StreamReader(PubKeyFile))
            {
                var parameters = new CspParameters
                {
                    KeyContainerName = KeyName,
                    Flags = CspProviderFlags.UseMachineKeyStore
                };
                _rsa = new RSACryptoServiceProvider(KeySize, parameters);

                string keytxt = sr.ReadToEnd();
                _rsa.FromXmlString(keytxt);
                _rsa.PersistKeyInCsp = true;

                label1.Text = _rsa.PublicOnly
                    ? $"Key: {parameters.KeyContainerName} - Public Only"
                    : $"Key: {parameters.KeyContainerName} - Full Key Pair";
            }
        }

        private void buttonGetPrivateKey_Click(object sender, EventArgs e)
        {
            var parameters = new CspParameters
            {
                KeyContainerName = KeyName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            _rsa = new RSACryptoServiceProvider(KeySize, parameters)
            {
                PersistKeyInCsp = true
            };

            label1.Text = _rsa.PublicOnly
                ? $"Key: {parameters.KeyContainerName} - Public Only"
                : $"Key: {parameters.KeyContainerName} - Full Key Pair";

            //var lPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), @"Microsoft\Crypto\RSA\MachineKeys");
            //var cp = new CspParameters();
            //cp.KeyContainerName = KeyName;
            //var lContainerInfo = new CspKeyContainerInfo(cp);
            //string lFilename = lContainerInfo.UniqueKeyContainerName;

            GetKeyFromContainer();
        }

        private static void GetKeyFromContainer()
        {
            // Create the CspParameters object and set the key container
            // name used to store the RSA key pair.
            var parameters = new CspParameters
            {
                KeyContainerName = KeyName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };

            // Create a new instance of RSACryptoServiceProvider that accesses
            // the key container MyKeyContainerName.
            var rsa = new RSACryptoServiceProvider(KeySize, parameters);

            File.WriteAllText("Key.xml", rsa.ToXmlString(true));

            // Display the key information to the console.
            //Console.WriteLine($"Key retrieved from container : \n {}");
        }

        private void buttonClearKey_Click(object sender, EventArgs e)
        {
            var cp = new CspParameters { KeyContainerName = KeyName,
                Flags = CspProviderFlags.UseMachineKeyStore
            };
            // Create a new instance of RSACryptoServiceProvider that accesses
            // the key container.
            var rsa = new RSACryptoServiceProvider(KeySize, cp) { PersistKeyInCsp = false };

            // Delete the key entry in the container.

            // Call Clear to release resources and delete the key from the container.
            rsa.Clear();
        }

        private bool CheckKeyExist()
        {
            var cspParams = new CspParameters
            {
                Flags = CspProviderFlags.UseExistingKey | CspProviderFlags.UseMachineKeyStore,
                KeyContainerName = KeyName
            };

            try
            {
                new RSACryptoServiceProvider(KeySize, cspParams);
            }
            catch (Exception)
            {
                return false;
            }
            return true;
        }

        private void buttonImportKeyFromXml_Click(object sender, EventArgs e)
        {
            if (_decryptOpenFileDialog.ShowDialog() == DialogResult.OK)
            {
                string fName = _encryptOpenFileDialog.FileName;

                var prm = new CspParameters
                {
                    KeyContainerName = KeyName,
                    Flags = CspProviderFlags.UseMachineKeyStore
                };

                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(KeySize, prm))
                {
                    using (FileStream fs = new FileStream(fName, FileMode.Open))
                    {
                        using (StreamReader sr = new StreamReader(fs))
                        {
                            rsa.FromXmlString(sr.ReadToEnd());
                            //txtImportKeyContainer.Text = rsa.CspKeyContainerInfo.KeyContainerName;
                        }
                    }
                }
            }

           
        }

        private void buttonKeyExist_Click(object sender, EventArgs e)
        {
            MessageBox.Show(this.CheckKeyExist() ? "La clé existe" : "La clé n'existe pas", "Msg", MessageBoxButtons.OK);
        }

        
    }
}
