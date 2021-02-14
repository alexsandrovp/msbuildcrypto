using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Diagnostics;

namespace msbuild.crypto
{
    /// <summary>
    /// Utility task to read a secret from a file stored on your build server
    /// Useful for getting passwords to servers/services
    /// </summary>
    public class DPAPIDecrypt : Task
    {
        /// <summary>
        /// File storing the secret
        /// </summary>
        [Required]
        public string InputFile { get; set; } = null;

        /// <summary>
        /// either "user" or "machine"
        /// </summary>
        public string EncryptionScope
        {
            get { return encryptionScope.ToString(); }
            set { encryptionScope = (DataProtectionScope)Enum.Parse(typeof(DataProtectionScope), value, true); }
        }
        private DataProtectionScope encryptionScope = DataProtectionScope.CurrentUser;

        /// <summary>
        /// optional entropy (utf8 bytes)
        /// </summary>
        public string Entropy { get; set; } = null;

        /// <summary>
        /// optional entropy file (raw bytes)
        /// </summary>
        public string EntropyFile { get; set; } = null;

        /// <summary>
        /// task output (decrypted secret)
        /// </summary>
        [Output]
        public string Decrypted { get; set; }

        public override bool Execute()
        {
            try
            {
                if (!validate()) return false;

                byte[] bytes = File.ReadAllBytes(InputFile);

                byte[] customEntropy = DPAPIHelper.getCustomEntropy(Entropy, EntropyFile);
                bytes = ProtectedData.Unprotect(bytes, customEntropy, encryptionScope);

                Decrypted = Encoding.UTF8.GetString(bytes);

                return true;
            }
            catch (Exception ex)
            {
                Log.LogError("exception in task DPAPIGetSecret");
                Log.LogError("{0}", ex);
            }
            return false;
        }

        private bool validate()
        {
            if (string.IsNullOrWhiteSpace(InputFile))
            {
                Log.LogError("SecretFile is required");
                return false;
            }

            if (!File.Exists(InputFile))
            {
                Log.LogError("SecretFile does not exist: {0}", InputFile);
                return false;
            }

            bool hasEntropy = !string.IsNullOrWhiteSpace(Entropy);
            bool hasEntropyFile = !string.IsNullOrWhiteSpace(EntropyFile);

            if (hasEntropy && hasEntropyFile)
            {
                Log.LogWarning("Ignoring EntropyFile because Entropy was used");
                EntropyFile = null;
                hasEntropyFile = false;
            }

            if (hasEntropyFile && !File.Exists(EntropyFile))
            {
                Log.LogError("EntropyFile does not exist: {0}", EntropyFile);
                return false;
            }

            return true;
        }
    }

    /// <summary>
    /// You can use this task to create a secret file through an msbuild project,
    /// or you can call directly using powershell:
    /// 
    /// PS > Add-Type -Path msbuild.crypto.dll
    /// PS > [msbuild.crypto.DPAPIWriteSecret]::WriteSecretFile("P@ssw0rd", "c:\users\myself\password.secret", $true, $null, $null)
    /// </summary>
    public class DPAPIEncrypt : Task
    {
        /// <summary>
        /// secret to store
        /// </summary>
        [Required]
        public string ToEncrypt { get; set; } = null;

        /// <summary>
        /// File storing the secret
        /// </summary>
        [Required]
        public string OutputFile { get; set; } = null;

        public bool Overwrite { get; set; } = false;

        /// <summary>
        /// either "user" or "machine"
        /// </summary>
        public string EncryptionScope
        {
            get { return encryptionScope.ToString(); }
            set { encryptionScope = (DataProtectionScope)Enum.Parse(typeof(DataProtectionScope), value, true); }
        }
        private DataProtectionScope encryptionScope = DataProtectionScope.CurrentUser;

        /// <summary>
        /// optional entropy (utf8 bytes)
        /// </summary>
        public string Entropy { get; set; } = null;

        /// <summary>
        /// optional entropy file (raw bytes)
        /// </summary>
        public string EntropyFile { get; set; } = null;

        public override bool Execute()
        {
#if DEBUG
            if (!Debugger.IsAttached)
            {
                var pid = Process.GetCurrentProcess().Id;
                Log.LogWarning("attach debugger to PID {0}, press any key to continue", pid);
                Console.ReadKey();
            }
#endif
            try
            {
                if (!validate()) return false;

                FileInfo fi = new FileInfo(OutputFile);

                byte[] bytes = Encoding.UTF8.GetBytes(ToEncrypt);
                byte[] customEntropy = DPAPIHelper.getCustomEntropy(Entropy, EntropyFile);
                bytes = ProtectedData.Protect(bytes, customEntropy, encryptionScope);

                if (!fi.Directory.Exists)
                    Directory.CreateDirectory(fi.Directory.FullName);

                File.WriteAllBytes(OutputFile, bytes);
                return true;
            }
            catch (Exception ex)
            {
                Log.LogError("exception in task DPAPIWriteSecret");
                Log.LogError("{0}", ex);
            }
            return false;
        }

        public static void WriteEncryptedFile(string toEncrypt, string outputFile,
            bool machineScope, string entropyStr, string entropyFile)
        {
            try
            {
                DPAPIHelper.writeSecretFile(toEncrypt, outputFile, machineScope, entropyStr, entropyFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine("exception: {0}", ex);
            }
        }

        private bool validate()
        {
            if (string.IsNullOrWhiteSpace(ToEncrypt))
            {
                Log.LogError("Secret is required");
                return false;
            }

            if (string.IsNullOrWhiteSpace(OutputFile))
            {
                Log.LogError("SecretFile is required");
                return false;
            }

            if (File.Exists(OutputFile))
            {
                if (Overwrite) Log.LogWarning("overwriting file: {0}", new FileInfo(OutputFile).FullName);
                else
                {
                    Log.LogError("output file already exists: {0}", new FileInfo(OutputFile).FullName);
                    return false;
                }
            }

            bool hasEntropy = !string.IsNullOrWhiteSpace(Entropy);
            bool hasEntropyFile = !string.IsNullOrWhiteSpace(EntropyFile);

            if (hasEntropy && hasEntropyFile)
            {
                Log.LogWarning("Ignoring EntropyFile because Entropy was used");
                EntropyFile = null;
                hasEntropyFile = false;
            }

            if (hasEntropyFile && !File.Exists(EntropyFile))
            {
                Log.LogError("EntropyFile does not exist: {0}", EntropyFile);
                return false;
            }

            return true;
        }
    }

    internal class DPAPIHelper
    {
        internal static byte[] getCustomEntropy(string entropyStr = null, string entropyFile = null)
        {
            bool hasEntropy = !string.IsNullOrWhiteSpace(entropyStr);
            bool hasEntropyFile = !string.IsNullOrWhiteSpace(entropyFile);

            if (hasEntropy && hasEntropyFile)
                throw new Exception("cannot use entropyStr and entropyFile at the same time");

            if (hasEntropyFile && !File.Exists(entropyFile))
                throw new Exception("entropyFile does not exist: " + entropyFile);

            byte[] customEntropy = null;
            if (hasEntropy) customEntropy = Encoding.UTF8.GetBytes(entropyStr);
            else if(hasEntropyFile) customEntropy = File.ReadAllBytes(entropyFile);

            if (customEntropy == null)
                customEntropy = Resources.entropy;
            else
            {
                List<byte> tempb = new List<byte>(Resources.entropy);
                tempb.AddRange(customEntropy);
                customEntropy = tempb.ToArray();
            }

            return customEntropy;
        }

        internal static void writeSecretFile(string secret, string filePath, bool machineScope, string entropyStr, string entropyFile)
        {
            FileInfo fi = new FileInfo(filePath);
            if (fi.Exists) throw new Exception("file already exists: " + fi.FullName);

            byte[] customEntropy = getCustomEntropy(entropyStr, entropyFile);
            var scope = machineScope ? DataProtectionScope.LocalMachine : DataProtectionScope.CurrentUser;
            byte[] bytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), customEntropy, scope);

            if (!fi.Directory.Exists)
                Directory.CreateDirectory(fi.Directory.FullName);

            File.WriteAllBytes(fi.FullName, bytes);
        }
    }
}
