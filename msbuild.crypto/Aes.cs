using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace msbuild.crypto
{
    public class AesDecrypt : Task
    {
        /// <summary>
        /// File storing the secret
        /// </summary>
        [Required]
        public string InputFile { get; set; } = null;

        /// <summary>
        /// Required encryption password
        /// </summary>
        [Required]
        public string Password { get; set; }

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

        private byte[] iv = null;
        private byte[] key = null;

        private byte[] getHash(byte[] bytes)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(bytes);
            }
        }

        private byte[] getHash(string filePath)
        {
            using (var sha = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    return sha.ComputeHash(stream);
                }
            }
        }

        private bool validate()
        {
            if (!File.Exists(InputFile))
            {
                Log.LogError("secret file does not exist: {0}", new FileInfo(InputFile).FullName);
                return false;
            }

            key = getHash(Encoding.UTF8.GetBytes(Password)).Take(32).ToArray();

            List<byte> entropy = new List<byte>(100000);
            entropy.AddRange(Resources.entropy);
            if (!string.IsNullOrEmpty(Entropy))
            {
                entropy.AddRange(Encoding.UTF8.GetBytes(Entropy));
                if (!string.IsNullOrWhiteSpace(EntropyFile))
                    Log.LogWarning("ignoring parameter EntropyFile because Entropy is being used");
            }
            else if (!string.IsNullOrWhiteSpace(EntropyFile))
            {
                if (!File.Exists(EntropyFile))
                {
                    Log.LogError("entropy file does not exist: {0}", new FileInfo(EntropyFile).FullName);
                    return false;
                }
                entropy.AddRange(getHash(EntropyFile));
            }

            iv = getHash(entropy.ToArray()).Take(16).ToArray();

            if (iv == null || iv.Length == 0)
            {
                Log.LogError("empty entropy");
                return false;
            }

            return true;
        }

        private string readStream(Stream stream)
        {
            List<byte> result = new List<byte>(51409800);
            byte[] buffer = new byte[51409800]; //50kB
            while (stream.CanRead)
            {
                int count = stream.Read(buffer, 0, buffer.Length);
                if (count <= 0) break;
                result.AddRange(buffer.Take(count).ToArray());
            }
            return Encoding.UTF8.GetString(result.ToArray());
        }

        public override bool Execute()
        {
            try
            {
                if (!validate()) return false;

                using (var aes = new AesManaged())
                {
                    using (var decryptor = aes.CreateDecryptor(key, iv))
                    {
                        using (var fs = File.OpenRead(InputFile))
                        {
                            using (var cs = new CryptoStream(fs, decryptor, CryptoStreamMode.Read))
                            {
                                Decrypted = readStream(cs);
                            }
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.LogError("{0}", ex);
            }
            return false;
        }
    }

    public class AesEncrypt : Task
    {
        /// <summary>
        /// secret to encrypt
        /// </summary>
        [Required]
        public string ToEncrypt { get; set; }

        /// <summary>
        /// File that will store the secret
        /// </summary>
        [Required]
        public string OutputFile { get; set; } = null;

        public bool Overwrite { get; set; } = false;

        /// <summary>
        /// Required encryption password
        /// </summary>
        [Required]
        public string Password { get; set; }

        /// <summary>
        /// optional entropy (utf8 bytes)
        /// </summary>
        public string Entropy { get; set; } = null;

        /// <summary>
        /// optional entropy file (raw bytes)
        /// </summary>
        public string EntropyFile { get; set; } = null;

        private byte[] iv = null;
        private byte[] key = null;

        private static byte[] getHash(byte[] bytes)
        {
            using (var sha = SHA256.Create())
            {
                return sha.ComputeHash(bytes);
            }
        }

        private static byte[] getHash(string filePath)
        {
            using (var sha = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    return sha.ComputeHash(stream);
                }
            }
        }

        private bool validate()
        {
            if (File.Exists(OutputFile))
            {
                if (Overwrite) Log.LogWarning("overwriting file: {0}", new FileInfo(OutputFile).FullName);
                else
                {
                    Log.LogError("secret file already exists: {0}", new FileInfo(OutputFile).FullName);
                    return false;
                }
            }

            key = getHash(Encoding.UTF8.GetBytes(Password)).Take(32).ToArray();

            List<byte> entropy = new List<byte>(100000);
            entropy.AddRange(Resources.entropy);
            if (!string.IsNullOrEmpty(Entropy))
            {
                entropy.AddRange(Encoding.UTF8.GetBytes(Entropy));
                if (!string.IsNullOrWhiteSpace(EntropyFile))
                    Log.LogWarning("ignoring parameter EntropyFile because Entropy is being used");
            }
            else if (!string.IsNullOrWhiteSpace(EntropyFile))
            {
                if (!File.Exists(EntropyFile))
                {
                    Log.LogError("entropy file does not exist: {0}", new FileInfo(EntropyFile).FullName);
                    return false;
                }
                entropy.AddRange(getHash(EntropyFile));
            }

            iv = getHash(entropy.ToArray()).Take(16).ToArray();

            if (iv == null || iv.Length == 0)
            {
                Log.LogError("empty entropy");
                return false;
            }

            return true;
        }

        public override bool Execute()
        {
            try
            {
                if (!validate()) return false;

                using (var aes = new AesManaged())
                {
                    using (var encryptor = aes.CreateEncryptor(key, iv))
                    {
                        using (var ms = new MemoryStream())
                        {
                            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                            {
                                byte[] bytes = Encoding.UTF8.GetBytes(ToEncrypt);
                                cs.Write(bytes, 0, bytes.Length);
                                cs.FlushFinalBlock();
                                var encrypted = ms.ToArray();
                                File.WriteAllBytes(OutputFile, encrypted);
                            }
                        }
                    }
                }

                return true;
            }
            catch (Exception ex)
            {
                Log.LogError("{0}", ex);
            }
            return false;
        }

        public static void WriteEncryptedFile(string toEncrypt, string outputFile,
            string password, string entropyStr, string entropyFile)
        {
            if (File.Exists(outputFile))
            {
                Console.WriteLine("secret file already exists: {0}", new FileInfo(outputFile).FullName);
                return;
            }

            var key = getHash(Encoding.UTF8.GetBytes(password)).Take(32).ToArray();

            List<byte> entropy = new List<byte>(100000);
            entropy.AddRange(Resources.entropy);
            if (!string.IsNullOrEmpty(entropyStr))
            {
                entropy.AddRange(Encoding.UTF8.GetBytes(entropyStr));
                if (!string.IsNullOrWhiteSpace(entropyFile))
                    Console.Write("ignoring parameter EntropyFile because Entropy is being used");
            }
            else if (!string.IsNullOrWhiteSpace(entropyFile))
            {
                if (!File.Exists(entropyFile))
                {
                    Console.WriteLine("entropy file does not exist: {0}", new FileInfo(entropyFile).FullName);
                    return;
                }
                entropy.AddRange(getHash(entropyFile));
            }

            var iv = getHash(entropy.ToArray()).Take(16).ToArray();

            if (iv == null || iv.Length == 0)
            {
                Console.WriteLine("empty entropy");
                return;
            }

            using (var aes = new AesManaged())
            {
                using (var encryptor = aes.CreateEncryptor(key, iv))
                {
                    using (var ms = new MemoryStream())
                    {
                        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                        {
                            byte[] bytes = Encoding.UTF8.GetBytes(toEncrypt);
                            cs.Write(bytes, 0, bytes.Length);
                            cs.FlushFinalBlock();
                            var encrypted = ms.ToArray();
                            File.WriteAllBytes(outputFile, encrypted);
                            Console.WriteLine("\nSuccess\n");
                        }
                    }
                }
            }
        }
    }
}
