using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace EVotingSystem.Services.Cryptography
{
    public static class CryptoHelper
    {
        public static string GetSha256Hash(string rawData)
        {
            using var sha256 = SHA256.Create();
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return Convert.ToBase64String(bytes);
        }

        public static string HashPassword(string password)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(16);
            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            byte[] hash = pbkdf2.GetBytes(32);
            return $"{Convert.ToBase64String(salt)}:{Convert.ToBase64String(hash)}";
        }

        public static bool VerifyPassword(string password, string storedHash)
        {
            var parts = storedHash.Split(':');
            if (parts.Length != 2)
                return false;

            byte[] salt = Convert.FromBase64String(parts[0]);
            byte[] expectedHash = Convert.FromBase64String(parts[1]);

            using var pbkdf2 = new Rfc2898DeriveBytes(password, salt, 100000, HashAlgorithmName.SHA256);
            byte[] actualHash = pbkdf2.GetBytes(32);

            return CryptographicOperations.FixedTimeEquals(expectedHash, actualHash);
        }

        public static string EncryptVoteDataWithAes(string plainTextVote, out byte[] aesKey)
        {
            var random = new SecureRandom();
            aesKey = new byte[32];
            byte[] nonce = new byte[12];

            random.NextBytes(aesKey);
            random.NextBytes(nonce);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(aesKey), 128, nonce);
            cipher.Init(true, parameters);

            byte[] inputBytes = Encoding.UTF8.GetBytes(plainTextVote);
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];

            int len = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, len);

            byte[] finalResult = new byte[nonce.Length + outputBytes.Length];
            Array.Copy(nonce, 0, finalResult, 0, nonce.Length);
            Array.Copy(outputBytes, 0, finalResult, nonce.Length, outputBytes.Length);

            return Convert.ToBase64String(finalResult);
        }

        public static string DecryptVoteDataWithAes(string encryptedData, byte[] aesKey)
        {
            byte[] fullData = Convert.FromBase64String(encryptedData);
            byte[] nonce = new byte[12];
            byte[] cipherText = new byte[fullData.Length - 12];

            Array.Copy(fullData, 0, nonce, 0, 12);
            Array.Copy(fullData, 12, cipherText, 0, cipherText.Length);

            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(aesKey), 128, nonce);
            cipher.Init(false, parameters);

            byte[] outputBytes = new byte[cipher.GetOutputSize(cipherText.Length)];
            int len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, len);

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
        }

        public static string EncryptAesKeyWithRsa(byte[] aesKey, AsymmetricKeyParameter publicKey)
        {
            var engine = new OaepEncoding(new RsaEngine());
            engine.Init(true, publicKey);
            return Convert.ToBase64String(engine.ProcessBlock(aesKey, 0, aesKey.Length));
        }

        public static byte[] DecryptAesKeyWithRsa(string encryptedKey, AsymmetricKeyParameter privateKey)
        {
            var engine = new OaepEncoding(new RsaEngine());
            engine.Init(false, privateKey);
            byte[] bytes = Convert.FromBase64String(encryptedKey);
            return engine.ProcessBlock(bytes, 0, bytes.Length);
        }

        public static string SignVote(string encryptedData, string encryptedSessionKey, AsymmetricKeyParameter voterPrivateKey)
        {
            string dataToSign = encryptedData + encryptedSessionKey;
            byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);

            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, voterPrivateKey);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);

            return Convert.ToBase64String(signer.GenerateSignature());
        }

        public static bool VerifyVoteSignature(string encryptedData, string encryptedSessionKey, string base64Signature, AsymmetricKeyParameter voterPublicKey)
        {
            try
            {
                string dataToVerify = encryptedData + encryptedSessionKey;
                byte[] dataBytes = Encoding.UTF8.GetBytes(dataToVerify);
                byte[] sigBytes = Convert.FromBase64String(base64Signature);

                ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
                signer.Init(false, voterPublicKey);
                signer.BlockUpdate(dataBytes, 0, dataBytes.Length);

                return signer.VerifySignature(sigBytes);
            }
            catch
            {
                return false;
            }
        }

        public static string SignReport(string reportData, AsymmetricKeyParameter orgPrivateKey)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(reportData);

            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, orgPrivateKey);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);

            return Convert.ToBase64String(signer.GenerateSignature());
        }

        private static byte[] GetOrCreateServerHmacKey()
        {
            string pkiRoot = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PKI_ROOT");
            if (!Directory.Exists(pkiRoot))
                Directory.CreateDirectory(pkiRoot);

            string keyPath = Path.Combine(pkiRoot, "server_hmac.key");

            if (!File.Exists(keyPath))
            {
                byte[] key = RandomNumberGenerator.GetBytes(32);
                File.WriteAllBytes(keyPath, key);
            }

            return File.ReadAllBytes(keyPath);
        }

        public static string CalculateHmac(string data)
        {
            byte[] key = GetOrCreateServerHmacKey();
            using var hmac = new HMACSHA256(key);
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
            return Convert.ToBase64String(hash);
        }

        public static string CalculateBallotHmac(int electionId, string encryptedData, string encryptedSessionKey, string receiptHash, DateTime timestamp)
        {
            string payload = $"{electionId}|{encryptedData}|{encryptedSessionKey}|{receiptHash}|{timestamp:o}";
            return CalculateHmac(payload);
        }
    }
}