namespace LemonCypher

open System;
open System.Text
open System.Security.Cryptography
open System.Buffers.Binary

module LemonCypher =

  let aesGen (password : string) =
    // Derive key
    // AES key size is 16 bytes
    // We use a fixed salt and small iteration count here; the latter should be increased for weaker password
    let key = (new Rfc2898DeriveBytes(password, (Array.zeroCreate 8), 1000)).GetBytes(16)
    
    // Initialize AES implementation
    new AesGcm(key)

  let encrypt (aes : AesGcm) (plain : string) =
    // Get bytes of plaintext string
    let plainBytes = Encoding.UTF8.GetBytes plain
  
    // Get parameter sizes
    let nonceSize = AesGcm.NonceByteSizes.MaxSize
    let tagSize = AesGcm.TagByteSizes.MaxSize
    let cipherSize = plainBytes.Length
  
    // We write everything into one big array for easier encoding
    let encryptedDataLength = 4 + nonceSize + 4 + tagSize + cipherSize
    let encryptedData = (Array.zeroCreate encryptedDataLength).AsSpan()
  
    // Copy parameters
    BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(0, 4), nonceSize)
    BinaryPrimitives.WriteInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4), tagSize)
    let nonce = encryptedData.Slice(4, nonceSize)
    let tag = encryptedData.Slice(4 + nonceSize + 4, tagSize)
    let cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize)
  
    // Generate secure nonce
    RandomNumberGenerator.Fill(nonce)
  
    // Encrypt
    aes.Encrypt((Span.op_Implicit nonce), (Span.op_Implicit(plainBytes.AsSpan())), cipherBytes, tag)
  
    // Encode for transmission
    Convert.ToBase64String (Span.op_Implicit encryptedData)
  
  let decrypt (aes : AesGcm) cipher =
    // Decode
    let encryptedData = ReadOnlySpan<byte> (Convert.FromBase64String cipher)
  
    // Extract parameter sizes
    let nonceSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(0, 4))
    let tagSize = BinaryPrimitives.ReadInt32LittleEndian(encryptedData.Slice(4 + nonceSize, 4))
    let cipherSize = encryptedData.Length - 4 - nonceSize - 4 - tagSize
  
    // Extract parameters
    let nonce = encryptedData.Slice(4, nonceSize)
    let tag = encryptedData.Slice(4 + nonceSize + 4, tagSize)
    let cipherBytes = encryptedData.Slice(4 + nonceSize + 4 + tagSize, cipherSize)
  
    // Decrypt
    let plainBytes : Span<byte> = (Array.zeroCreate cipherSize).AsSpan()
    aes.Decrypt(nonce, cipherBytes, tag, plainBytes)
  
    // Convert plain bytes back into string
    Encoding.UTF8.GetString (Span.op_Implicit plainBytes)

//module LemonCypher = //v1 2020-02-12
//  //Hack This is unsecure.
//  let private PasswordHash = "5f042e659d16ada62bd286483a753db6"
//  let private SaltKey = "7721e347f38ca532afefa365095d648e"
//  let private VIKey = "acc5eb9d0$0866e9"
//  let private VIKey2 = "abc5eb9d0$0899e9"

//  (*I don't actually know what these are doing. Immprovents in security will be incoming*)

//  let encrypt (plainText : string) =
//    let viKey = Encoding.ASCII.GetBytes(VIKey)
//    let plainTextBytes = Encoding.UTF8.GetBytes(plainText)
//    let keyBytes = (new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey))).GetBytes(256 / 8)
//    use symmetricKey = new RijndaelManaged( Mode = CipherMode.CBC, Padding = PaddingMode.ISO10126 )
//    use encryptor = symmetricKey.CreateEncryptor(keyBytes, viKey)
//    use memoryStream = new MemoryStream()
//    use cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)
//    cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length)
//    cryptoStream.FlushFinalBlock()
//    Convert.ToBase64String(memoryStream.ToArray())

//  let decrypt encryptedText =
//    let cipherTextBytes = Convert.FromBase64String(encryptedText)
//    let keyBytes = (new Rfc2898DeriveBytes(PasswordHash, Encoding.ASCII.GetBytes(SaltKey))).GetBytes(256 / 8)
//    use symmetricKey = new RijndaelManaged( Mode = CipherMode.CBC, Padding = PaddingMode.ISO10126 )
//    use decryptor = symmetricKey.CreateDecryptor(keyBytes, Encoding.ASCII.GetBytes(VIKey2))
//    use cryptoStream = new CryptoStream(new MemoryStream(cipherTextBytes), decryptor, CryptoStreamMode.Read)
//    let plainTextBytes = Array.zeroCreate cipherTextBytes.Length
//    let decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length)
//    Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount).TrimEnd([|'\u0000'|])