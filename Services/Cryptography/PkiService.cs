using System;
using System.IO;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace EVotingSystem.Services.Cryptography
{
    public class PkiService
    {
        private readonly string _pkiPath;
        private readonly string _rootPath;
        private readonly string _orgCaPath;
        private readonly string _voterCaPath;
        private readonly string _crlPath;

        public PkiService()
        {
            // bin/Debug/net8.0/PKI_ROOT
            _pkiPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "PKI_ROOT");
            _rootPath = Path.Combine(_pkiPath, "RootCA");
            _orgCaPath = Path.Combine(_pkiPath, "OrgCA");
            _voterCaPath = Path.Combine(_pkiPath, "VoterCA");
            _crlPath = Path.Combine(_pkiPath, "CRLs");

            InitializePkiInfrastructure();
        }

        private void InitializePkiInfrastructure()
        {
            if (!Directory.Exists(_pkiPath))
            {
                Directory.CreateDirectory(_pkiPath);
                Directory.CreateDirectory(_rootPath);
                Directory.CreateDirectory(_orgCaPath);
                Directory.CreateDirectory(_voterCaPath);
                Directory.CreateDirectory(_crlPath);

                // ROOT CA
                var rootKeys = GenerateKeyPair(4096);
                var rootCert = GenerateRootCertificate(rootKeys);
                SaveCertificate(rootCert, _rootPath, "root.crt");
                SavePrivateKey(rootKeys.Private, _rootPath, "root.key");

                // Org CA (Potpisuje ga Root)
                var orgKeys = GenerateKeyPair(2048);
                var orgCert = GenerateIntermediateCertificate(orgKeys.Public, rootKeys.Private, rootCert, "CN=EVoting Organization CA, O=EVoting, C=BA");
                SaveCertificate(orgCert, _orgCaPath, "org.crt");
                SavePrivateKey(orgKeys.Private, _orgCaPath, "org.key");

                // Voter CA (Potpisuje ga Root)
                var voterKeys = GenerateKeyPair(2048);
                var voterCert = GenerateIntermediateCertificate(voterKeys.Public, rootKeys.Private, rootCert, "CN=EVoting Voter CA, O=EVoting, C=BA");
                SaveCertificate(voterCert, _voterCaPath, "voter.crt");
                SavePrivateKey(voterKeys.Private, _voterCaPath, "voter.key");

                // prazne CRL liste
                InitializeCrl(_orgCaPath, "org.key", "org.crt", Path.Combine(_crlPath, "org.crl"));
                InitializeCrl(_voterCaPath, "voter.key", "voter.crt", Path.Combine(_crlPath, "voter.crl"));
            }
        }

        // GENERISANJE KLJUCEVA
        public AsymmetricCipherKeyPair GenerateKeyPair(int strength)
        {
            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            return keyPairGenerator.GenerateKeyPair();
        }

        // ROOT CA CERT
        private X509Certificate GenerateRootCertificate(AsymmetricCipherKeyPair keys)
        {
            var random = new SecureRandom();
            var certGen = new X509V3CertificateGenerator();

            // Serijski broj
            var serialNumber = BigInteger.ProbablePrime(120, new Random());
            certGen.SetSerialNumber(serialNumber);

            // Izdavač i Subjekt isti (self-signed)
            var issuerDN = new X509Name("CN=EVoting Root CA, O=EVoting, C=BA");
            certGen.SetIssuerDN(issuerDN);
            certGen.SetSubjectDN(issuerDN);

            // Validnost (20 godina)
            certGen.SetNotBefore(DateTime.UtcNow.Date);
            certGen.SetNotAfter(DateTime.UtcNow.Date.AddYears(20));

            certGen.SetPublicKey(keys.Public);

            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign));

            // Potpisivanje (SHA256 sa RSA)
            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", keys.Private, random);
            return certGen.Generate(signatureFactory);
        }

        // INTERMEDIATE CA
        private X509Certificate GenerateIntermediateCertificate(AsymmetricKeyParameter publicKey, AsymmetricKeyParameter caPrivateKey, X509Certificate caCert, string subjectName)
        {
            var random = new SecureRandom();
            var certGen = new X509V3CertificateGenerator();

            var serialNumber = BigInteger.ProbablePrime(120, new Random());
            certGen.SetSerialNumber(serialNumber);

            certGen.SetIssuerDN(caCert.SubjectDN);
            certGen.SetSubjectDN(new X509Name(subjectName));

            certGen.SetNotBefore(DateTime.UtcNow.Date);
            certGen.SetNotAfter(DateTime.UtcNow.Date.AddYears(10));

            certGen.SetPublicKey(publicKey);

            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.DigitalSignature));

#pragma warning disable CS0618
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCert));
#pragma warning restore CS0618

            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", caPrivateKey, random);
            return certGen.Generate(signatureFactory);
        }

        private void SaveCertificate(X509Certificate cert, string path, string filename)
        {
            var filePath = Path.Combine(path, filename);
            using (var writer = new StreamWriter(filePath))
            {
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(cert);
            }
        }

        private void SavePrivateKey(AsymmetricKeyParameter key, string path, string filename)
        {
            var filePath = Path.Combine(path, filename);
            using (var writer = new StreamWriter(filePath))
            {
                // U praksi ključ treba biti enkriptovan passwordom, 
                // ovdje čuvamo kao PEM radi jednostavnosti simulacije serverske strane.
                var pemWriter = new PemWriter(writer);
                pemWriter.WriteObject(key);
            }
        }

        private void InitializeCrl(string caPath, string keyName, string certName, string crlOutput)
        {
            if (!File.Exists(crlOutput))
            {
                File.WriteAllText(crlOutput, "");
            }
        }

        public string RegisterUserCertificate(string username, string password, string commonName, bool isOrganizer, out string serialNumberHex)
        {
            // issuer
            string issuerDir = isOrganizer ? _orgCaPath : _voterCaPath;
            string issuerPrefix = isOrganizer ? "org" : "voter";

            X509Certificate issuerCert = ReadCertificate(Path.Combine(issuerDir, $"{issuerPrefix}.crt"));
            AsymmetricKeyParameter issuerPrivKey = ReadPrivateKey(Path.Combine(issuerDir, $"{issuerPrefix}.key"));

            var userKeys = GenerateKeyPair(2048);

            var random = new SecureRandom();
            var certGen = new X509V3CertificateGenerator();

            var serialNumber = BigInteger.ProbablePrime(120, new Random());
            serialNumberHex = serialNumber.ToString(16);
            certGen.SetSerialNumber(serialNumber);

            certGen.SetIssuerDN(issuerCert.SubjectDN);
            certGen.SetSubjectDN(new X509Name($"CN={commonName}, UID={username}, C=BA"));

            certGen.SetNotBefore(DateTime.UtcNow.Date);
            certGen.SetNotAfter(DateTime.UtcNow.Date.AddYears(2));

            certGen.SetPublicKey(userKeys.Public);

            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            certGen.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment | KeyUsage.NonRepudiation));

#pragma warning disable CS0618
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(issuerCert));
#pragma warning restore CS0618

            // Potpisivanje
            var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", issuerPrivKey, random);
            var userCert = certGen.Generate(signatureFactory);

            var builder = new Pkcs12StoreBuilder();
            var store = builder.Build();

            X509Certificate rootCert = ReadCertificate(Path.Combine(_rootPath, "root.crt"));

            var certEntry = new X509CertificateEntry(userCert);
            var chain = new[] { certEntry, new X509CertificateEntry(issuerCert), new X509CertificateEntry(rootCert) };

            store.SetKeyEntry(username, new AsymmetricKeyEntry(userKeys.Private), chain);

            string userCertsDir = Path.Combine(_pkiPath, "UserCerts");
            if (!Directory.Exists(userCertsDir))
                Directory.CreateDirectory(userCertsDir);

            string p12Path = Path.Combine(userCertsDir, $"{username}.p12");

            using (var stream = new FileStream(p12Path, FileMode.Create, FileAccess.Write))
            {
                store.Save(stream, password.ToCharArray(), random);
            }

            return p12Path;
        }
        
        private X509Certificate ReadCertificate(string path)
        {
            using (var reader = File.OpenText(path))
            {
                var pemReader = new PemReader(reader);
                return (X509Certificate)pemReader.ReadObject();
            }
        }

        private AsymmetricKeyParameter ReadPrivateKey(string path)
        {
            using (var reader = File.OpenText(path))
            {
                var pemReader = new PemReader(reader);
                var keyObj = pemReader.ReadObject();

                if (keyObj is AsymmetricCipherKeyPair pair)
                    return pair.Private;

                return (AsymmetricKeyParameter)keyObj;
            }
        }

        public bool ValidateAndExtractCertificate(string p12Path, string password, out string serialNumberHex, out string errorMessage)
        {
            serialNumberHex = string.Empty;
            errorMessage = string.Empty;

            try
            {
                var builder = new Pkcs12StoreBuilder();
                var store = builder.Build();

                using (var stream = new FileStream(p12Path, FileMode.Open, FileAccess.Read))
                {
                    store.Load(stream, password.ToCharArray()); 
                }

                string alias = null;
                foreach (string a in store.Aliases)
                {
                    if (store.IsKeyEntry(a))
                    {
                        alias = a;
                        break;
                    }
                }

                if (alias == null)
                {
                    errorMessage = "Fajl ne sadrži privatni ključ i sertifikat.";
                    return false;
                }

                var certEntry = store.GetCertificate(alias);
                var cert = certEntry.Certificate;

                try
                {
                    cert.CheckValidity(DateTime.UtcNow);
                }
                catch (Org.BouncyCastle.Security.Certificates.CertificateExpiredException)
                {
                    errorMessage = "Ovaj sertifikat je istekao.";
                    return false;
                }
                catch (Org.BouncyCastle.Security.Certificates.CertificateNotYetValidException)
                {
                    errorMessage = "Ovaj sertifikat još uvijek nije validan.";
                    return false;
                }

                serialNumberHex = cert.SerialNumber.ToString(16);
                return true;
            }
            catch (Exception ex)
            {
                errorMessage = "Neispravna lozinka ili oštećen .p12 fajl.";
                return false;
            }
        }

        public void RevokeCertificate(string serialNumberHex, bool isOrganizer)
        {
        }
    }
}