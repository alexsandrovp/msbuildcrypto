# msbuildcrypto
cryptography tasks for msbuild

This is an .net assembly with custom tasks for msbuild to handle common cryptography commands.


## Quick start

A typical msbuild project has the following format
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
	<Target Name="Build">
		<Message Text="This is my build" />
	</Target>
</Project>
```

To import an assembly, use the `<UsingTask>` element, specifying which class/taks you want to import
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
	
	<!--======================================================================-->
	<UsingTask AssemblyFile="msbuild.crypto.dll" TaskName="msbuild.crypto.DPAPIDecrypt" />
	<!--======================================================================-->
	
	<Target Name="Build">
		<Message Text="This is my build" />
	</Target>
</Project>
```

Then, just use the imported class/task
```xml
<?xml version="1.0" encoding="utf-8"?>
<Project DefaultTargets="Build" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
	
	<UsingTask AssemblyFile="msbuild.crypto.dll" TaskName="msbuild.crypto.DPAPIDecrypt" />
	<Target Name="Build">
		
		<!--======================================================================-->
		<DPAPIDecrypt SecretFile="c:\passwords\github.password" Encrypted="true">
				<Output TaskParameter="Secret" PropertyName="Password" />
		</DPAPIDecrypt>
		<!--======================================================================-->
		
		<Message Text="My password: $(Password)" />
	</Target>
</Project>
```

The entropy used to encrypt a secret must be used again to decrypt it.
If you use EntropyFile as source of entropy, make sure you never modify that file,
otherwise you will never be able to decrypt your secret again.

The project has an __entropy.bin__ file that is used in case a custom source of entropy is not provided in the project xml. Feel free to replace that file with any other you want and compile a custom version of msbuild.crypto.dll.

<br><br>

## Available tasks

[DPAPIDecrypt](#DPAPIDecrypt)
[DPAPIEncrypt](#DPAPIEncrypt)
[AesDecrypt](#AesDecrypt)
[AesEncrypt](#AesEncrypt)
[CertDecrypt](#CertDecrypt)
[CertEncrypt](#CertEncrypt)

### <a name="DPAPIDecrypt"></a>DPAPIDecrypt

Reads encrypted data from a file and decrypts it using Windows DPAPI

```xml
<DPAPIDecrypt InputFile="github.password"
	EntropyFile="c:\entropy.jpg" EncryptionScope="LocalMachine">
	<Output TaskParameter="Decrypted" Property="MyProperty" />
</DPAPIDecrypt>
```

__InputFile__ (required): file where the secret is stored

__Entropy__ (optional): string whose utf8 bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'EntropyFile'

__EntropyFile__ (optional): file whose raw bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'Entropy'

__EncryptionScope__ (optional): either "CurrentUser" or "LocalMachine". Default: "CurrentUser"

__Decrypted__ (output): receives the decrypted content of InputFile

### <a name="DPAPIEncrypt"></a>DPAPIEncrypt

Writes an encrypted string to a file using Windows DPAPI.

```xml
<DPAPIEncrypt ToEncrypt="this is my password" OutputFile="github.password"
	EntropyFile="c:\entropy.jpg" EncryptionScope="LocalMachine" />
```

__ToEncrypt__ (required): what to encrypt

__OutputFile__ (required): file where the secret is stored

__Overwrite__ (optional): Boolean that indicates if the output file can be overwritten (generates a warning) or not (default, generates an error)

__Entropy__ (optional): string whose utf8 bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'EntropyFile'

__EntropyFile__ (optional): file whose raw bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'Entropy'

__EncryptionScope__ (optional): either "CurrentUser" or "LocalMachine". Default: "CurrentUser"

### <a name="AesDecrypt"></a>AesDecrypt

Reads encrypted data from a file and decrrypts it using Aes.

```xml
<AesDecrypt InputFile="github.password" Password="abc123" EntropyFile="c:\entropy.jpg">
	<Output TaskParameter="Decrypted" Property="MyProperty" />
</AesDecrypt>
```

__InputFile__ (required): file where the secret is stored

__Password__ (required): encryption password

__Entropy__ (optional): string whose utf8 bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'EntropyFile'

__EntropyFile__ (optional): file whose raw bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'Entropy'

__Decrypted__ (output): receives the decrypted content of InputFile

### <a name="AesEncrypt"></a>AesEncrypt

Writes an encrypted string to a file using Aes encryption.

```xml
<AesEncrypt ToEncrypt="this is my password" OutputFile="github.password"
	EntropyFile="c:\entropy.jpg" Password="abc123" />
```

__ToEncrypt__ (required): what to encrypt

__Password__ (required): encryption password

__OutputFile__ (required): file where the secret is stored

__Overwrite__ (optional): Boolean that indicates if the output file can be overwritten (generates a warning) or not (default, generates an error)

__Entropy__ (optional): string whose utf8 bytes are used as additional entropy for AES. Sort of an extra password. Cannot be used with 'EntropyFile'

__EntropyFile__ (optional): file whose raw bytes are used as additional entropy for AES. Sort of an extra password. Cannot be used with 'Entropy'

### <a name="CertDecrypt"></a>CertDecrypt

Reads encrypted data from a file and decrypts it using the private key of a certificate stored in your system. You must specify at least one of the following optional parameters: Thumbprint, Issuer, Subject or FriendlyName.

```xml
<CertDecrypt InputFile="github.password"
	StoreLocation="LocalMachine" StoreName="TrustedPublisher" Thumbprint="C7E2EB699ACC">
	<Output TaskParameter="Decrypted" Property="MyProperty" />
</CertDecrypt>
```

__InputFile__ (required): file where the secret is stored

__StoreLocation__ (optional): location where to search the certificate for. Can be either "CurrentUser" (default) or "LocalMachine"

__StoreName__ (optional): name of the store where to search the certificate for. The default is "My" (you personal certificates). Look at [StoreName Enum](#https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storename) for possible values.

__Thumbprint__ (optional): part of the thumbprint of the certificate that must be selected.

__Issuer__ (optional): part of the issuer name of the certificate that must be selected.

__Subject__ (optional): part of the subject name of the certificate that must be selected.

__FriendlyName__ (optional): part of the friendly name of the certificate that must be selected.

__Decrypted__ (output): receives the decrypted content of InputFile

### <a name="CertEncrypt"></a>CertEncrypt

Writes an encrypted string to a file, using the public key of one of your certificates. You must specify at least one of the following optional parameters: Thumbprint, Issuer, Subject or FriendlyName.

```xml
<CertEncrypt ToEncrypt="this is my password" OutputFile="github.password" Thumbprint="C7E2EB699ACC" />
```

__ToEncrypt__ (required): what to encrypt

__OutputFile__ (required): file where the secret is stored

__Overwrite__ (optional): Boolean that indicates if the output file can be overwritten (generates a warning) or not (default, generates an error)

__StoreLocation__ (optional): location where to search the certificate for. Can be either "CurrentUser" (default) or "LocalMachine"

__StoreName__ (optional): name of the store where to search the certificate for. The default is "My" (you personal certificates). Look at [StoreName Enum](#https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.storename) for possible values.

__Thumbprint__ (optional): part of the thumbprint of the certificate that must be selected.

__Issuer__ (optional): part of the issuer name of the certificate that must be selected.

__Subject__ (optional): part of the subject name of the certificate that must be selected.

__FriendlyName__ (optional): part of the friendly name of the certificate that must be selected.

<br><br>

## Static functions

__[msbuild.crypto.DPAPIEncrypt]::WriteEncryptedFile__
__[msbuild.crypto.AesEncrypt]::WriteEncryptedFile__
__[msbuild.crypto.CertEncrypt]::WriteEncryptedFile__

These are public static methods that can be used directly from powershell to encrypt a message without having to create an msbuild project.

```powershell
PS> Add-Type -Path msbuild.crypto.dll
PS> [msbuild.crypto.DPAPIEncrypt]::WriteEncryptedFile($secretText, $pathToSecretFile, $useMachineScope, $optionalEntropyText, $optionalEntropyFile)
```

```powershell
PS> Add-Type -Path msbuild.crypto.dll
PS> [msbuild.crypto.AesEncrypt]::WriteEncryptedFile($toEncrypt, $outputFile, $password, $entropyStr, $entropyFile)
```

where you either use __$optionalEntropyText__ or __$optionalEntropyFile__, setting the other to $null

```powershell
PS> Add-Type -Path msbuild.crypto.dll
PS> [msbuild.crypto.CertEncrypt]::WriteEncryptedFile($toEncrypt, $outputFile, $storeLocation, $storeName, $thumbprint, $issuer, $subject, $friendlyName)
```