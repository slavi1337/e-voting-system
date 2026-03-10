using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

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
    }
}