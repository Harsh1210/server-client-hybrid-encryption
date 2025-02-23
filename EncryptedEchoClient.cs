using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using hw2_encryption;

/// <summary>
/// Provides a base class for implementing an Echo client.
/// </summary>
internal sealed class EncryptedEchoClient : EchoClientBase {

    /// <summary>
    /// Logger to use in this class.
    /// </summary>
    private ILogger<EncryptedEchoClient> Logger { get; init; } =
        Settings.LoggerFactory.CreateLogger<EncryptedEchoClient>()!;

    private RSA rsa;
    private byte[]? serverPublicKey;

    /// <inheritdoc />
    public EncryptedEchoClient(ushort port, string address) : base(port, address) {
        rsa = RSA.Create();
    }

    /// <inheritdoc />
    public override void ProcessServerHello(string message) {
        // todo: Step 1: Get the server's public key. Decode using Base64.
        // Throw a CryptographicException if the received key is invalid.
        try {
            serverPublicKey = Convert.FromBase64String(message);
            rsa.ImportRSAPublicKey(serverPublicKey, out _);
        } catch (Exception) {
            throw new CryptographicException("Invalid server public key.");
        }
    }

    /// <inheritdoc />
    public override string TransformOutgoingMessage(string input) {
        byte[] data = Settings.Encoding.GetBytes(input);

        // todo: Step 1: Encrypt the input using hybrid encryption.
        // Encrypt using AES with CBC mode and PKCS7 padding.
        // Use a different key each time.
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();
        var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
        byte[] encryptedMessage;
        using (var ms = new MemoryStream())
        using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
        {
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();
            encryptedMessage = ms.ToArray();
        }

        // todo: Step 2: Generate an HMAC of the message.
        // Use the SHA256 variant of HMAC.
        // Use a different key each time.
        using var hmac = new HMACSHA256();
        hmac.Key = RandomNumberGenerator.GetBytes(32);
        var hmacValue = hmac.ComputeHash(data);

        // todo: Step 3: Encrypt the message encryption and HMAC keys using RSA.
        // Encrypt using the OAEP padding scheme with SHA256.
        var encryptedKey = rsa.Encrypt(aes.Key, RSAEncryptionPadding.OaepSHA256);
        var encryptedHmacKey = rsa.Encrypt(hmac.Key, RSAEncryptionPadding.OaepSHA256);

        // todo: Step 4: Put the data in an EncryptedMessage object and serialize to JSON.
        // Return that JSON.
        // var message = new EncryptedMessage(...);
        // return JsonSerializer.Serialize(message);
        var message = new EncryptedMessage {
            AesKeyWrap = encryptedKey,
            AESIV = aes.IV,
            Message = encryptedMessage,
            HMACKeyWrap = encryptedHmacKey,
            HMAC = hmacValue
        };
        return JsonSerializer.Serialize(message);
    }

    /// <inheritdoc />
    public override string TransformIncomingMessage(string input) {
        // todo: Step 1: Deserialize the message.
        // var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);
        var signedMessage = JsonSerializer.Deserialize<SignedMessage>(input);

        // todo: Step 2: Check the messages signature.
        // Use PSS padding with SHA256.
        // Throw an InvalidSignatureException if the signature is bad.
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(signedMessage.Message);
        if (!rsa.VerifyHash(hash, signedMessage.Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidSignatureException();

        // todo: Step 3: Return the message from the server.
        // return Settings.Encoding.GetString(signedMessage.Message);
        return Settings.Encoding.GetString(signedMessage.Message);
    }
}