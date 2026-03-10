using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using System.Security.Cryptography;
using System.Text;

namespace EVotingSystem.Services.Cryptography
{
    public static class CryptoHelper
    {
        public static string ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));
                StringBuilder builder = new StringBuilder();
                foreach (byte b in bytes)
                    builder.Append(b.ToString("x2"));
                return builder.ToString();
            }
        }

        public static string EncryptVoteDataWithAes(string plainTextVote, out byte[] aesKey)
        {
            var random = new SecureRandom();
            aesKey = new byte[32];
            byte[] iv = new byte[16];

            random.NextBytes(aesKey);
            random.NextBytes(iv);

            var engine = new AesEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            var keyParam = new KeyParameter(aesKey);
            var paramsWithIv = new ParametersWithIV(keyParam, iv);

            cipher.Init(true, paramsWithIv);
            byte[] inputBytes = Encoding.UTF8.GetBytes(plainTextVote);
            byte[] outputBytes = new byte[cipher.GetOutputSize(inputBytes.Length)];

            int length = cipher.ProcessBytes(inputBytes, 0, inputBytes.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            byte[] finalResult = new byte[iv.Length + outputBytes.Length];
            Array.Copy(iv, 0, finalResult, 0, iv.Length);
            Array.Copy(outputBytes, 0, finalResult, iv.Length, outputBytes.Length);

            return Convert.ToBase64String(finalResult);
        }

        public static string EncryptAesKeyWithRsa(byte[] aesKey, AsymmetricKeyParameter organizerPublicKey)
        {
            var engine = new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(new RsaEngine());
            engine.Init(true, organizerPublicKey);

            byte[] encryptedKey = engine.ProcessBlock(aesKey, 0, aesKey.Length);
            return Convert.ToBase64String(encryptedKey);
        }

        public static string SignVote(string encryptedData, string encryptedSessionKey, AsymmetricKeyParameter voterPrivateKey)
        {
            string dataToSign = encryptedData + encryptedSessionKey;
            byte[] dataBytes = Encoding.UTF8.GetBytes(dataToSign);

            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, voterPrivateKey);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
            byte[] signature = signer.GenerateSignature();

            return Convert.ToBase64String(signature);
        }

        public static byte[] DecryptAesKeyWithRsa(string encryptedSessionKey, AsymmetricKeyParameter organizerPrivateKey)
        {
            var engine = new Org.BouncyCastle.Crypto.Encodings.Pkcs1Encoding(new RsaEngine());
            engine.Init(false, organizerPrivateKey);
            byte[] keyBytes = Convert.FromBase64String(encryptedSessionKey);
            return engine.ProcessBlock(keyBytes, 0, keyBytes.Length);
        }

        public static string DecryptVoteDataWithAes(string encryptedData, byte[] aesKey)
        {
            byte[] fullData = Convert.FromBase64String(encryptedData);
            byte[] iv = new byte[16];
            byte[] cipherText = new byte[fullData.Length - 16];

            Array.Copy(fullData, 0, iv, 0, 16);
            Array.Copy(fullData, 16, cipherText, 0, cipherText.Length);

            var engine = new AesEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var cipher = new PaddedBufferedBlockCipher(blockCipher, new Pkcs7Padding());

            cipher.Init(false, new ParametersWithIV(new KeyParameter(aesKey), iv));
            byte[] outputBytes = new byte[cipher.GetOutputSize(cipherText.Length)];

            int length = cipher.ProcessBytes(cipherText, 0, cipherText.Length, outputBytes, 0);
            cipher.DoFinal(outputBytes, length);

            return Encoding.UTF8.GetString(outputBytes).TrimEnd('\0');
        }

        public static string SignReport(string reportData, AsymmetricKeyParameter orgPrivateKey)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(reportData);
            ISigner signer = SignerUtilities.GetSigner("SHA-256withRSA");
            signer.Init(true, orgPrivateKey);
            signer.BlockUpdate(dataBytes, 0, dataBytes.Length);
            byte[] signature = signer.GenerateSignature();
            return Convert.ToBase64String(signature);
        }

        private static readonly byte[] ServerHmacKey = Encoding.UTF8.GetBytes("TajniKljucAplikacijeZaEVoting123!");

        public static string CalculateHmac(string data)
        {
            using (var hmac = new HMACSHA256(ServerHmacKey))
            {
                byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
                return Convert.ToBase64String(hash);
            }
        }
    }
}