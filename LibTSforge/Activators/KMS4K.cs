namespace LibTSforge.Activators {
  using System;
  using System.IO;
  using PhysicalStore;
  using SPP;

  public class KMS4k {
    public static void Activate(PSVersion version, bool production, Guid actId) {
      Guid appId;
      if (actId == Guid.Empty) {
        appId = SLApi.WINDOWS_APP_ID;
        actId = SLApi.GetDefaultActivationID(appId, true);

        if (actId == Guid.Empty) {
          throw new NotSupportedException("No applicable activation IDs found.");
        }
      } else {
        appId = SLApi.GetAppId(actId);
      }

      if (SLApi.GetPKeyChannel(SLApi.GetInstalledPkeyID(actId)) != "Volume:GVLK") {
        throw new NotSupportedException("Non-Volume:GVLK product key installed.");
      }

      SPPUtils.KillSPP(version);

      Logger.WriteLine("Writing TrustedStore data...");

      using(IPhysicalStore store = SPPUtils.GetStore(version, production)) {
        string key = string.Format("SPPSVC\\{0}\\{1}", appId, actId);

        ulong unknown = 0;
        ulong time1;
        ulong time2 = (ulong) DateTime.UtcNow.ToFileTime();
        ulong expiry = Constants.TimerMax;

        int buildNumber = Environment.OSVersion.Version.Build;
        bool isActualVista = (buildNumber >= 6000 && buildNumber <= 6003);
        bool useVistaFormat = false;

        if (isActualVista) {
          Logger.WriteLine("Detected actual Vista (build " + buildNumber + "), using Vista format");
          unknown = 0x800000000;
          time1 = 0;
          useVistaFormat = true;
        } else {
          Logger.WriteLine("Detected Win7-style build (" + buildNumber + ")");

          // Try to get Win7-style time blocks
          try {
            PSBlock creationBlock = store.GetBlock("__##USERSEP##\\$$_RESERVED_$$\\NAMESPACE__", "__##USERSEP-RESERVED##__$$GLOBAL-CREATION-TIME$$");
            PSBlock tickCountBlock = store.GetBlock("__##USERSEP##\\$$_RESERVED_$$\\NAMESPACE__", "__##USERSEP-RESERVED##__$$GLOBAL-TICKCOUNT-UPTIME$$");
            PSBlock deltaBlock = store.GetBlock(key, "__##USERSEP-RESERVED##__$$UP-TIME-DELTA$$");

            if (creationBlock != null && tickCountBlock != null && deltaBlock != null) {
              long creationTime = BitConverter.ToInt64(creationBlock.Data, 0);
              long tickCount = BitConverter.ToInt64(tickCountBlock.Data, 0);
              long deltaTime = BitConverter.ToInt64(deltaBlock.Data, 0);

              time1 = (ulong)(creationTime + tickCount + deltaTime);
              time2 /= 10000;
              expiry /= 10000;

              Logger.WriteLine("Using Win7 timer format");
              useVistaFormat = false;
            } else {
              Logger.WriteLine("Win7 time blocks not found, using Vista format");
              unknown = 0x800000000;
              time1 = 0;
              useVistaFormat = true;
            }
          } catch (Exception ex) {
            Logger.WriteLine("Failed to read Win7 time blocks: " + ex.Message);
            Logger.WriteLine("Falling back to Vista format");
            unknown = 0x800000000;
            time1 = 0;
            useVistaFormat = true;
          }
        }

        if (useVistaFormat) {
          Logger.WriteLine("Writing Vista-style KMS blocks");

          // Vista timer uses full FileTime, not divided
          VistaTimer vistaTimer = new VistaTimer {
            Time = (ulong) DateTime.UtcNow.ToFileTime(),
              Expiry = Constants.TimerMax
          };

          string vistaTimerName = string.Format("msft:sl/timer/VLExpiration/VOLUME/{0}/{1}", appId, actId);
          string vistaDataName = actId.ToString();

          // Delete existing blocks
          store.DeleteBlock(key, vistaTimerName);
          store.DeleteBlock(key, vistaDataName);

          // Build KMS response data: length + response + hwid
          BinaryWriter writer = new BinaryWriter(new MemoryStream());
          writer.Write(Constants.KMSv4Response.Length);
          writer.Write(Constants.KMSv4Response);
          writer.Write(Constants.UniversalHWIDBlock);
          byte[] kmsData = writer.GetBytes();

          Logger.WriteLine("Key: " + key);
          Logger.WriteLine("Timer value: " + vistaTimerName);
          Logger.WriteLine("Data value: " + vistaDataName);
          Logger.WriteLine("Timer data: Time=0x" + vistaTimer.Time.ToString("X") + " Expiry=0x" + vistaTimer.Expiry.ToString("X"));
          Logger.WriteLine("KMS data length: 0x" + kmsData.Length.ToString("X"));

          store.AddBlocks(new [] {
            new PSBlock {
              Type = BlockType.TIMER,
                Flags = 0,
                KeyAsStr = key,
                ValueAsStr = vistaTimerName,
                Data = vistaTimer.CastToArray()
            },
            new PSBlock {
              Type = BlockType.NAMED,
                Flags = 0,
                KeyAsStr = key,
                ValueAsStr = vistaDataName,
                Data = kmsData
            }
          });

          Logger.WriteLine("Vista KMS blocks written successfully");
        } else {
          Logger.WriteLine("Writing Win7-style KMS blocks");

          byte[] hwidBlock = Constants.UniversalHWIDBlock;
          byte[] kmsResp;

          if (version == PSVersion.Vista || version == PSVersion.Win7) {
            kmsResp = Constants.KMSv4Response;
          } else if (version == PSVersion.Win8) {
            kmsResp = Constants.KMSv5Response;
          } else if (version == PSVersion.WinBlue || version == PSVersion.WinModern) {
            kmsResp = Constants.KMSv6Response;
          } else {
            throw new NotSupportedException("Unsupported PSVersion.");
          }

          VariableBag kmsBinding = new VariableBag(version);

          kmsBinding.Blocks.AddRange(new [] {
            new CRCBlockModern {
              DataType = CRCBlockType.BINARY,
                Key = new byte[] {},
                Value = kmsResp
            },
            new CRCBlockModern {
              DataType = CRCBlockType.STRING,
                Key = new byte[] {},
                ValueAsStr = "msft:rm/algorithm/hwid/4.0"
            },
            new CRCBlockModern {
              DataType = CRCBlockType.BINARY,
                KeyAsStr = "SppBindingLicenseData",
                Value = hwidBlock
            }
          });

          if (version == PSVersion.WinModern) {
            kmsBinding.Blocks.AddRange(new [] {
              new CRCBlockModern {
                DataType = CRCBlockType.STRING,
                  Key = new byte[] {},
                  ValueAsStr = "massgrave.dev"
              },
              new CRCBlockModern {
                DataType = CRCBlockType.STRING,
                  Key = new byte[] {},
                  ValueAsStr = "6969"
              }
            });
          }

          byte[] kmsBindingData = kmsBinding.Serialize();

          Timer kmsTimer = new Timer {
            Unknown = unknown,
              Time1 = time1,
              Time2 = time2,
              Expiry = expiry
          };

          string storeVal = string.Format("msft:spp/kms/bind/2.0/store/{0}/{1}", appId, actId);
          string timerVal = string.Format("msft:spp/kms/bind/2.0/timer/{0}/{1}", appId, actId);

          store.DeleteBlock(key, storeVal);
          store.DeleteBlock(key, timerVal);

          uint timerFlags = (version == PSVersion.Win7 || version == PSVersion.Vista) ? (uint) 0 : 0x4;

          store.AddBlocks(new [] {
            new PSBlock {
              Type = BlockType.NAMED,
                Flags = (version == PSVersion.WinModern) ? (uint) 0x400 : 0,
                KeyAsStr = key,
                ValueAsStr = storeVal,
                Data = kmsBindingData
            },
            new PSBlock {
              Type = BlockType.TIMER,
                Flags = timerFlags,
                KeyAsStr = key,
                ValueAsStr = timerVal,
                Data = kmsTimer.CastToArray()
            }
          });
        }
      }

      SPPUtils.RestartSPP(version);
      SLApi.FireStateChangedEvent(appId);
      Logger.WriteLine("Activated using KMS4k successfully.");
    }
  }
}
