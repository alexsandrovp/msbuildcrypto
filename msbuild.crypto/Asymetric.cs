using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace msbuild.crypto
{
    static class AsymHelper
    {
        public static X509Certificate2 SelectCertificate(bool requirePrivateKey, StoreLocation scope, StoreName name,
            string thumbprint, string subject, string friendlyName, string issuer)
        {
            using (var store = new X509Store(name, scope))
            {
                store.Open(OpenFlags.ReadOnly);

                thumbprint = thumbprint == null ? "" : thumbprint.ToUpper();
                friendlyName = friendlyName == null ? "" : friendlyName.ToUpper();
                subject = subject == null ? "" : subject.ToUpper();

                bool mustMatchThumb = !string.IsNullOrEmpty(thumbprint);
                bool mustMatchSubject = !string.IsNullOrEmpty(subject);
                bool mustMatchFriendlyName = !string.IsNullOrEmpty(friendlyName);
                bool mustMatchIssuer = !string.IsNullOrEmpty(issuer);

                foreach (var certificate in store.Certificates)
                {
                    if (requirePrivateKey && !certificate.HasPrivateKey) continue;

                    bool thumbMatch = !mustMatchThumb || (!string.IsNullOrEmpty(certificate.Thumbprint) && certificate.Thumbprint.ToUpper().Contains(thumbprint));
                    bool subjectMatch = !mustMatchSubject || (!string.IsNullOrEmpty(certificate.Subject) && certificate.Subject.ToUpper().Contains(subject));
                    bool friendlyNameMatch = !mustMatchFriendlyName || (!string.IsNullOrEmpty(certificate.FriendlyName) && certificate.FriendlyName.ToUpper().Contains(friendlyName));
                    bool issuerMatch = !mustMatchIssuer || (!string.IsNullOrEmpty(certificate.Issuer) && certificate.Issuer.ToUpper().Contains(issuer));

                    if (thumbMatch && subjectMatch && friendlyNameMatch && issuerMatch)
                    {
                        if (requirePrivateKey)
                        {
                            try { var privateKey = certificate.GetRSAPrivateKey(); }
                            catch (CryptographicException) { continue; }
                        }

                        return certificate;
                    }
                }
            }
            return null;
        }
    }

    public class CertEncrypt : Task
    {
        /// <summary>
        /// message to encrypt
        /// </summary>
        [Required]
        public string ToEncrypt { get; set; }

        /// <summary>
        /// File to store the encrypted message
        /// </summary>
        [Required]
        public string OutputFile { get; set; }

        public bool Overwrite { get; set; } = false;

        /// <summary>
        /// Search for certificates in this store location
        /// </summary>
        public StoreLocation StoreLocation { get; set; } = StoreLocation.CurrentUser;

        /// <summary>
        /// Search for certificates in this store
        /// </summary>
        public StoreName StoreName { get; set; } = StoreName.My;

        /// <summary>
        /// Search certificates matching this thumbprint
        /// </summary>
        public string Thumbprint { get; set; }

        /// <summary>
        /// Search certificates matching this issuer
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Search for certificates matching this subject
        /// </summary>
        public string Subject { get; set; }

        /// <summary>
        /// Search for certificates matching this friendly name
        /// </summary>
        public string FriendlyName { get; set; }

        private X509Certificate2 certificate = null;

        private bool validate()
        {
            if (string.IsNullOrEmpty(Thumbprint) && string.IsNullOrEmpty(Issuer) && string.IsNullOrEmpty(Subject) && string.IsNullOrEmpty(FriendlyName))
            {
                Log.LogError("no certificate data provided (must use at least one of Thumbprint, Issuer, Subject or FriendlyName)");
                return false;
            }

            certificate = AsymHelper.SelectCertificate(false, StoreLocation, StoreName, Thumbprint, Subject, FriendlyName, Issuer);
            if (certificate == null)
            {
                Log.LogError("could not find a certificate that has a usable private key and matches the given data");
                return false;
            }

            if (File.Exists(OutputFile))
            {
                if (Overwrite) Log.LogWarning("overwriting file: {0}", new FileInfo(OutputFile).FullName);
                else
                {
                    Log.LogError("file already exists: {0}. Maybe you intent to use Overwrite=\"true\"?", new FileInfo(OutputFile).FullName);
                    return false;
                }
            }

            return true;
        }

        public override bool Execute()
        {
            if (!validate()) return false;

            var encrypted = certificate.GetRSAPublicKey().Encrypt(Encoding.UTF8.GetBytes(ToEncrypt), RSAEncryptionPadding.Pkcs1);
            File.WriteAllBytes(OutputFile, encrypted);

            return true;
        }

        public static void WriteEncryptedFile(string toEncrypt, string outputFile,
            StoreLocation storeLocation, StoreName storeName,
            string thumbprint, string issuer, string subject, string friendlyName)
        {
            if (string.IsNullOrEmpty(thumbprint) && string.IsNullOrEmpty(issuer) && string.IsNullOrEmpty(subject) && string.IsNullOrEmpty(friendlyName))
            {
                Console.WriteLine("no certificate data provided (must use at least one of Thumbprint, Issuer, Subject or FriendlyName)");
                return;
            }

            var certificate = AsymHelper.SelectCertificate(false, storeLocation, storeName, thumbprint, subject, friendlyName, issuer);
            if (certificate == null)
            {
                Console.WriteLine("could not find a certificate that has a usable private key and matches the given data");
                return;
            }

            if (File.Exists(outputFile))
            {
                Console.WriteLine("file already exists: {0}. Maybe you intent to use Overwrite=\"true\"?", new FileInfo(outputFile).FullName);
                return;
            }

            var encrypted = certificate.GetRSAPublicKey().Encrypt(Encoding.UTF8.GetBytes(toEncrypt), RSAEncryptionPadding.Pkcs1);
            File.WriteAllBytes(outputFile, encrypted);

            Console.WriteLine("\nSuccess\n");
        }

    }

    public class CertDecrypt : Task
    {
        /// <summary>
        /// File containing encrypted message
        /// </summary>
        [Required]
        public string InputFile { get; set; }

        /// <summary>
        /// Search for certificates in this store location
        /// </summary>
        public StoreLocation StoreLocation { get; set; } = StoreLocation.CurrentUser;

        /// <summary>
        /// Search for certificates in this store
        /// </summary>
        public StoreName StoreName { get; set; } = StoreName.My;

        /// <summary>
        /// Search certificates matching this thumbprint
        /// </summary>
        public string Thumbprint { get; set; }

        /// <summary>
        /// Search certificates matching this issuer
        /// </summary>
        public string Issuer { get; set; }

        /// <summary>
        /// Search for certificates matching this subject
        /// </summary>
        public string Subject { get; set; }

        /// <summary>
        /// Search for certificates matching this friendly name
        /// </summary>
        public string FriendlyName { get; set; }

        /// <summary>
        /// task output: decrypted message
        /// </summary>
        [Output]
        public string Decrypted { get; set; }

        X509Certificate2 certificate = null;

        private bool validate()
        {
            if (!File.Exists(InputFile))
            {
                Log.LogError("file does not exist: {0}.", new FileInfo(InputFile).FullName);
                return false;
            }

            if (string.IsNullOrEmpty(Thumbprint) && string.IsNullOrEmpty(Issuer) && string.IsNullOrEmpty(Subject) && string.IsNullOrEmpty(FriendlyName))
            {
                Log.LogError("no certificate data provided (must use at least one of Thumbprint, Issuer, Subject or FriendlyName)");
                return false;
            }

            certificate = AsymHelper.SelectCertificate(true, StoreLocation, StoreName, Thumbprint, Subject, FriendlyName, Issuer);
            if (certificate == null)
            {
                Log.LogError("could not find a certificate that has a usable private key and matches the given data");
                return false;
            }

            return true;
        }

        public override bool Execute()
        {
            try
            {
                if (!validate()) return false;

                var encrypted = File.ReadAllBytes(InputFile);
                var decrypted = certificate.GetRSAPrivateKey().Decrypt(encrypted, RSAEncryptionPadding.Pkcs1);
                Decrypted = Encoding.UTF8.GetString(decrypted);
                return true;
            }
            catch (CryptographicException ex)
            {
                Log.LogError("failed to decrypt {0}: {1}", new FileInfo(InputFile).FullName, ex.Message);
            }

            return false;
        }
    }
}
