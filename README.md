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
  <UsingTask AssemblyFile="msbuild.crypto.dll" TaskName="msbuild.crypto.DPAPIGetSecret" />
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
  
  <UsingTask AssemblyFile="msbuild.crypto.dll" TaskName="msbuild.crypto.DPAPIGetSecret" />
  <Target Name="Build">
    
    <!--======================================================================-->
    <DPAPIGetSecret SecretFile="c:\passwords\github.password" Encrypted="true">
        <Output TaskParameter="Secret" PropertyName="Password" />
    </GitGetSHA>
    <!--======================================================================-->
    
    <Message Text="My password: $(Password)" />
  </Target>
</Project>
```

The entropy used to encrypt a secret must be used again to decrypt it.
If you use EntropyFile as source of entropy, make sure you never modify that file,
otherwise you will never be able to decrypt your secret again.

## Available tasks

[DPAPIGetSecret](#DPAPIGetSecret)
[DPAPIWriteSecret](#DPAPIWriteSecret)

### <a name="DPAPIGetSecret"></a>DPAPIGetSecret

Reads the content of a file and stores it into a property

```xml
<DPAPIGetSecret Encrypted="true" SecretFile="github.password"
  EntropyFile="c:\entropy.jpg" EncryptionScope="machine">
  <Output TaskParameter="Secret" Property="MyProperty" />
</DPAPIGetSecret>
```

__SecretFile__ (required): file where the secret is stored

__Encrypted__ (optional): tells if the contents of SecretFile are encrypted. Default: __false__

__Entropy__ (optional): string whose utf8 bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'EntropyFile'

__EntropyFile__ (optional): file whose raw bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'Entropy'

__EncryptionScope__ (optional): either "user" or "machine". Default: "user"

__Secret__ (output): receives the decrypted content of SecretFile

### <a name="DPAPIWriteSecret"></a>DPAPIGetSecret

Writes a secret to a file in an encrypted form, using Windows DPAPI.

```xml
<DPAPIWriteSecret Secret="this is my password" SecretFile="github.password"
    EntropyFile="c:\entropy.jpg" EncryptionScope="machine" />
```

__Secret__ (required): what to encrypt

__SecretFile__ (required): file where the secret is stored

__Entropy__ (optional): string whose utf8 bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'EntropyFile'

__EntropyFile__ (optional): file whose raw bytes are used as additional entropy for DPAPI. Sort of an extra password. Cannot be used with 'Entropy'

__EncryptionScope__ (optional): either "user" or "machine". Default: "user"

There is a public static method (__[msbuild.crypto.DPAPIWriteSecret]::WriteSecretFile__) that can be used directly from powershell to encrypt a secret file without having to create an msbuild project:

```powershell
PS> Add-Type -Path msbuild.crypto.dll
PS> [msbuild.crypto.DPAPIWriteSecret]::WriteSecretFile($secretText, $pathToSecretFile, $useMachineScope, $optionalEntropyText, $optionalEntropyFile)
```

where you either use __$optionalEntropyText__ or __$optionalEntropyFile__, settings the other to $null
