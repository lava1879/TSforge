namespace LibTSforge.Crypto
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;

    public static class PhysStoreCrypto
    {
        public static byte[] DecryptPhysicalStore(byte[] data, bool production, PSVersion version)
        {
            byte[] rsaKey = production ? Keys.PRODUCTION : Keys.TEST;
            BinaryReader br = new BinaryReader(new MemoryStream(data));
            br.BaseStream.Seek(0x10, SeekOrigin.Begin);
            byte[] aesKeySig = br.ReadBytes(0x80);
            byte[] encAesKey = br.ReadBytes(0x80);

            if (!CryptoUtils.RSAVerifySignature(rsaKey, encAesKey, aesKeySig))
            {
                throw new Exception("Failed to decrypt physical store.");
            }

            byte[] aesKey = CryptoUtils.RSADecrypt(rsaKey, encAesKey);
            byte[] decData = CryptoUtils.AESDecrypt(br.ReadBytes((int)br.BaseStream.Length - 0x110), aesKey);
            byte[] hmacKey = decData.Take(0x10).ToArray(); // SHA-1 salt on Vista
            byte[] hmacSig = decData.Skip(0x10).Take(0x14).ToArray(); // SHA-1 hash on Vista
            byte[] psData = decData.Skip(0x28).ToArray();

            if (version != PSVersion.Vista)
            {
                if (!CryptoUtils.HMACVerify(hmacKey, psData, hmacSig))
                {
                    throw new InvalidDataException("Failed to verify HMAC. Physical store is corrupt.");
                }
            }
            else
            {
                if (!CryptoUtils.SaltSHAVerify(hmacKey, psData, hmacSig))
                {
                    throw new InvalidDataException("Failed to verify checksum. Physical store is corrupt.");
                }
            }

            return psData;
        }

        public static byte[] EncryptPhysicalStore(byte[] data, bool production, PSVersion version)
        {
            Dictionary<PSVersion, int> versionTable = new Dictionary<PSVersion, int>
            {
                {PSVersion.Vista, 2},
                {PSVersion.Win6469, 2},
                {PSVersion.Win7, 5},
                {PSVersion.Win8, 1},
                {PSVersion.WinBlue, 2},
                {PSVersion.WinModern, 3}
            };

            byte[] rsaKey = production ? Keys.PRODUCTION : Keys.TEST;

            byte[] aesKey = Encoding.UTF8.GetBytes("massgrave.dev :3");
            byte[] hmacKey = CryptoUtils.GenerateRandomKey(0x10);

            byte[] encAesKey = CryptoUtils.RSAEncrypt(rsaKey, aesKey);
            byte[] aesKeySig = CryptoUtils.RSASign(rsaKey, encAesKey);
            byte[] hmacSig = version != PSVersion.Vista ? CryptoUtils.HMACSign(hmacKey, data) : CryptoUtils.SaltSHASum(hmacKey, data);

            byte[] decData = { };
            decData = decData.Concat(hmacKey).Concat(hmacSig).Concat(BitConverter.GetBytes(0)).Concat(data).ToArray();
            byte[] encData = CryptoUtils.AESEncrypt(decData, aesKey);

            BinaryWriter bw = new BinaryWriter(new MemoryStream());
            bw.Write(versionTable[version]);
            bw.Write(Encoding.UTF8.GetBytes("UNTRUSTSTORE"));
            bw.Write(aesKeySig);
            bw.Write(encAesKey);
            bw.Write(encData);

            return bw.GetBytes();
        }
    }
}
