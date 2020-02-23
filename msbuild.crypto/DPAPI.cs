using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace msbuild.crypto
{
    /// <summary>
    /// Utility task to read a secret from a file stored on your build server
    /// Useful for getting passwords to servers/services
    /// </summary>
    public class DPAPIGetSecret : Task
    {
        /// <summary>
        /// File storing the secret
        /// </summary>
        [Required]
        public string SecretFile { get; set; } = null;

        /// <summary>
        /// true if we should decrypt the contents of SecretFile
        /// </summary>
        public bool Encrypted { get; set; } = false;

        /// <summary>
        /// either "user" or "machine"
        /// </summary>
        public string EncryptionScope { get; set; } = "user";

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
        public string Secret { get; set; }

        public override bool Execute()
        {
            try
            {
                if (!validate()) return false;

                byte[] bytes = File.ReadAllBytes(SecretFile);

                if (Encrypted)
                {
                    byte[] customEntropy = DPAPIHelper.getCustomEntropy(Entropy, EntropyFile);
                    DataProtectionScope scope = EncryptionScope == "user"
                        ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine;
                    bytes = ProtectedData.Unprotect(bytes, customEntropy, scope);
                }

                Secret = Encoding.UTF8.GetString(bytes);

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
            if (string.IsNullOrWhiteSpace(SecretFile))
            {
                Log.LogError("SecretFile is required");
                return false;
            }

            if (!File.Exists(SecretFile))
            {
                Log.LogError("SecretFile does not exist: {0}", SecretFile);
                return false;
            }

            if (Encrypted)
            {
                if (string.IsNullOrWhiteSpace(EncryptionScope))
                {
                    Log.LogError("empty EncryptionScope");
                    return false;
                }
                EncryptionScope = EncryptionScope.ToLower();
                if (EncryptionScope != "user" && EncryptionScope != "machine")
                {
                    Log.LogError("EncryptionScope must be 'user' or 'machine'");
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
            }

            return true;
        }
    }

    /// <summary>
    /// You can use this task to create a secret file through an msbuild project,
    /// or you can call directly using powershell:
    /// 
    /// PS > Add-Type -Path msbuild.git.dll
    /// PS > [msbuild.dpapi.DPAPIWriteSecret]::WriteSecretFile("P@ssw0rd", "c:\users\myself\password.secret", $true, $null, $null)
    /// </summary>
    public class DPAPIWriteSecret : Task
    {
        /// <summary>
        /// secret to store
        /// </summary>
        [Required]
        public string Secret { get; set; } = null;

        /// <summary>
        /// File storing the secret
        /// </summary>
        [Required]
        public string SecretFile { get; set; } = null;

        /// <summary>
        /// either "user" or "machine"
        /// </summary>
        public string EncryptionScope { get; set; } = "user";

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
            try
            {
                if (!validate()) return false;

                FileInfo fi = new FileInfo(SecretFile);
                if (fi.Exists) throw new Exception("file already exists: " + fi.FullName);

                byte[] bytes = Encoding.UTF8.GetBytes(Secret);
                byte[] customEntropy = DPAPIHelper.getCustomEntropy(Entropy, EntropyFile);
                DataProtectionScope scope = EncryptionScope == "user"
                    ? DataProtectionScope.CurrentUser : DataProtectionScope.LocalMachine;
                bytes = ProtectedData.Protect(bytes, customEntropy, scope);

                if (!fi.Directory.Exists)
                    Directory.CreateDirectory(fi.Directory.FullName);

                File.WriteAllBytes(SecretFile, bytes);
                return true;
            }
            catch (Exception ex)
            {
                Log.LogError("exception in task DPAPIWriteSecret");
                Log.LogError("{0}", ex);
            }
            return false;
        }

        public static void WriteSecretFile(string secret, string secretFile,
            bool machineScope, string entropyStr, string entropyFile)
        {
            try
            {
                DPAPIHelper.writeSecretFile(secret, secretFile, machineScope, entropyStr, entropyFile);
            }
            catch (Exception ex)
            {
                Console.WriteLine("exception: {0}", ex);
            }
        }

        private bool validate()
        {
            if (string.IsNullOrWhiteSpace(Secret))
            {
                Log.LogError("Secret is required");
                return false;
            }

            if (string.IsNullOrWhiteSpace(SecretFile))
            {
                Log.LogError("SecretFile is required");
                return false;
            }

            if (File.Exists(SecretFile))
            {
                Log.LogError("SecretFile already exists: {0}", SecretFile);
                return false;
            }

            if (string.IsNullOrWhiteSpace(EncryptionScope))
            {
                Log.LogError("empty EncryptionScope");
                return false;
            }
            EncryptionScope = EncryptionScope.ToLower();
            if (EncryptionScope != "user" && EncryptionScope != "machine")
            {
                Log.LogError("EncryptionScope must be 'user' or 'machine'");
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

    internal class DPAPIHelper
    {
        private static readonly byte[] entropy =
            new byte[] { 142, 105, 138, 16, 69, 248, 7, 103, 211, 145, 248, 120, 61, 244, 150, 12 };

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
            else customEntropy = File.ReadAllBytes(entropyFile);

            if (customEntropy == null)
                customEntropy = entropy;
            else
            {
                List<byte> tempb = new List<byte>(entropy);
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
