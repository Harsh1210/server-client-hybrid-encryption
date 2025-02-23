using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using hw2_encryption;

internal sealed class EncryptedEchoServer : EchoServerBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoServer> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoServer>()!;

    private RSA rsa;
    private byte[] publicKey;

    /// <inheritdoc />
    internal EncryptedEchoServer(ushort port) : base(port) {
    
    // todo: Step 1: Generate a RSA key (2048 bits) for the server.
        rsa = RSA.Create(2048);
        publicKey = rsa.ExportRSAPublicKey();
    }

    /// <inheritdoc />
    public override string GetServerHello() {
        // todo: Step 1: Send the public key to the client in PKCS#1 format.
        // Encode using Base64: Convert.ToBase64String
        return Convert.ToBase64String(publicKey);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        // var message = JsonSerializer.Deserialize<EncryptedMessage>(input);
        var message = JsonSerializer.Deserialize<hw2_encryption.EncryptedMessage>(input);

        // todo: Step 2: Decrypt the message using hybrid encryption.
        var decryptedKey = rsa.Decrypt(message.AesKeyWrap, RSAEncryptionPadding.OaepSHA256);
        var decryptedHmacKey = rsa.Decrypt(message.HMACKeyWrap, RSAEncryptionPadding.OaepSHA256);

        using var aes = Aes.Create();
        aes.Key = decryptedKey;
        aes.IV = message.AESIV;
        var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        byte[] decryptedMessage;
        using (var ms = new MemoryStream(message.Message))
        using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
        using (var reader = new MemoryStream())
        {
            cs.CopyTo(reader);
            decryptedMessage = reader.ToArray();
        }

        // todo: Step 3: Verify the HMAC.
        // Throw an InvalidSignatureException if the received hmac is bad.
        using var hmac = new HMACSHA256(decryptedHmacKey);
        var computedHmac = hmac.ComputeHash(decryptedMessage);
        if (!computedHmac.SequenceEqual(message.HMAC))
            throw new InvalidSignatureException();

        // todo: Step 3: Return the decrypted and verified message from the server.
        // return Settings.Encoding.GetString(decryptedMessage);
        return Settings.Encoding.GetString(decryptedMessage);
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Sign the message.
        // Use PSS padding with SHA256.
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(data);
        var signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        // todo: Step 2: Put the data in an SignedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new SignedMessage(...);
        // return JsonSerializer.Serialize(message);
        var message = new hw2_encryption.SignedMessage {
            Message = data,
            Signature = signature
        };
        return JsonSerializer.Serialize(message);
    }
}