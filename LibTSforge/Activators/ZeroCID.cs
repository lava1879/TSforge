namespace LibTSforge.Activators
{
    using System;
    using System.IO;
    using System.Linq;
    using Crypto;
    using PhysicalStore;
    using SPP;

    public static class ZeroCID
    {
        private static void Deposit(Guid actId, string instId)
        {
            uint status = SLApi.DepositConfirmationID(actId, instId, Constants.ZeroCID);
            Logger.WriteLine(string.Format("Depositing fake CID status {0:X}", status));

            if (status != 0)
            {
                throw new InvalidOperationException("Failed to deposit fake CID.");
            }
        }

        public static void Activate(PSVersion version, bool production, Guid actId)
        {
            Guid appId;

            if (actId == Guid.Empty)
            {
                appId = SLApi.WINDOWS_APP_ID;
                actId = SLApi.GetDefaultActivationID(appId, false);

                if (actId == Guid.Empty)
                {
                    throw new NotSupportedException("No applicable activation IDs found.");
                }
            }
            else
            {
                appId = SLApi.GetAppId(actId);
            }

            if (!SLApi.IsPhoneActivatable(actId))
            {
                throw new NotSupportedException("Phone license is unavailable for this product.");
            }

            string instId = SLApi.GetInstallationID(actId);
            Guid pkeyId = SLApi.GetInstalledPkeyID(actId);

            if (version == PSVersion.Vista)
            {
                Deposit(actId, instId);
            }

            SPPUtils.KillSPP(version);

            Logger.WriteLine("Writing TrustedStore data...");

            using (IPhysicalStore store = SPPUtils.GetStore(version, production))
            {
                byte[] hwidBlock = Constants.UniversalHWIDBlock;

                Logger.WriteLine("Activation ID: " + actId);
                Logger.WriteLine("Installation ID: " + instId);
                Logger.WriteLine("Product Key ID: " + pkeyId);

                byte[] iidHash;

                if (version == PSVersion.Vista)
                {
                    iidHash = CryptoUtils.SHA256Hash(Utils.EncodeString(instId));
                }
                else
                {
                    iidHash = CryptoUtils.SHA256Hash(Utils.EncodeString(instId + '\0' + Constants.ZeroCID));
                }

                string key = string.Format("SPPSVC\\{0}\\{1}", appId, actId);
                PSBlock keyBlock = store.GetBlock(key, pkeyId.ToString());

                if (keyBlock == null)
                {
                    throw new InvalidDataException("Failed to get product key data for activation ID " + actId + ".");
                }

                VariableBag pkb = new VariableBag(keyBlock.Data, version);

                byte[] pkeyData;

                if (version == PSVersion.Vista)
                {
                    CRCBlock shortAuth = pkb.GetBlock("SppPkeyShortAuthenticator");
                    
                    if (shortAuth != null)
                    {
                        pkeyData = shortAuth.Value;
                    }
                    else
                    {
                        CRCBlock basicInfo = pkb.GetBlock("PKeyBasicInfo");
                        
                        if (basicInfo == null)
                        {
                            throw new InvalidDataException("Failed to find product key data in variable bag.");
                        }
                        
                        pkeyData = basicInfo.Value;
                        string uniqueId = Utils.DecodeString(pkeyData.Skip(0x120).Take(0x80).ToArray());
                        string extPid = Utils.DecodeString(pkeyData.Skip(0x1A0).Take(0x80).ToArray());

                        uint group;
                        uint.TryParse(extPid.Split('-')[1], out group);

                        if (group == 0)
                        {
                            throw new FormatException("Extended PID has invalid format.");
                        }

                        ulong shortauth;

                        try
                        {
                            shortauth = BitConverter.ToUInt64(Convert.FromBase64String(uniqueId.Split('&')[1]), 0);
                        }
                        catch
                        {
                            throw new FormatException("Key Unique ID has invalid format.");
                        }

                        shortauth |= (ulong)group << 41;
                        pkeyData = BitConverter.GetBytes(shortauth);
                    }
                }
                else
                {
                    pkeyData = pkb.GetBlock("SppPkeyPhoneActivationData").Value;
                }

                pkb.DeleteBlock("SppPkeyVirtual");
                store.SetBlock(key, pkeyId.ToString(), pkb.Serialize());

                BinaryWriter writer = new BinaryWriter(new MemoryStream());
                writer.Write(iidHash.Length);
                writer.Write(iidHash);
                writer.Write(hwidBlock.Length);
                writer.Write(hwidBlock);
                byte[] tsHwidData = writer.GetBytes();

                writer = new BinaryWriter(new MemoryStream());
                writer.Write(iidHash.Length);
                writer.Write(iidHash);
                writer.Write(pkeyData.Length);
                writer.Write(pkeyData);
                byte[] tsPkeyInfoData = writer.GetBytes();

                string phoneVersion = "7.0";
                Guid indexSlid = pkeyId;
                string hwidBlockName = string.Format("msft:Windows/{0}/Phone/Cached/HwidBlock/{1}", phoneVersion, indexSlid);
                string pkeyInfoName = string.Format("msft:Windows/{0}/Phone/Cached/PKeyInfo/{1}", phoneVersion, indexSlid);

                store.DeleteBlock(key, hwidBlockName);
                store.DeleteBlock(key, pkeyInfoName);

                store.AddBlocks(new[] {
                    new PSBlock
                    {
                        Type = BlockType.NAMED,
                        Flags = 0,
                        KeyAsStr = key,
                        ValueAsStr = hwidBlockName,
                        Data = tsHwidData
                    },
                    new PSBlock
                    {
                        Type = BlockType.NAMED,
                        Flags = 0,
                        KeyAsStr = key,
                        ValueAsStr = pkeyInfoName,
                        Data = tsPkeyInfoData
                    }
                });
            }

            if (version != PSVersion.Vista)
            {
                Deposit(actId, instId);
            }

            SPPUtils.RestartSPP(version);
            SLApi.FireStateChangedEvent(appId);
            Logger.WriteLine("Activated using ZeroCID successfully.");
        }
    }
}
