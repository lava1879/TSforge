namespace TSforgeCLI {
  using System;
  using LibTSforge;
  using LibTSforge.Activators;
  using LibTSforge.Modifiers;
  using LibTSforge.SPP;

  public class Program {
    private class Options {
      public bool Dump;
      public string DumpFilePath = "dump.dat";
      public string EncrFilePath;
      public bool Load;
      public string LoadFilePath = "load.dat";
      public bool KMS4k;
      public bool AVMA4k;
      public bool ZCID;
      public bool TimerReset;
      public bool RearmReset;
      public bool DeleteUniqueId;
      public bool InstallGenPKey;
      public bool KMSHostCharge;
      public bool TamperedFlagsDelete;
      public bool KeyChangeLockDelete;
      public bool SetIIDParams;
      public bool ? Production;
      public PSVersion ? Version;
      public Guid ActivationId = Guid.Empty;
      public bool ShowHelp;
      public PKeyAlgorithm ? Algorithm;
      public int Group;
      public int Serial;
      public ulong Security;
      public bool Compare;
      public string CompareFile1;
      public string CompareFile2;

    }

    public static void Main(string[] args) {
      Logger.WriteLine("TSforge (c) MASSGRAVE 2025");

      Utils.Wow64EnableWow64FsRedirection(false);

      try {
        if (args.Length == 0) {
          DisplayUsage();
          return;
        }

        Options options = ParseArguments(args);

        if (options.ShowHelp) {
          DisplayUsage();
          return;
        }

        PSVersion version = options.Version ?? Utils.DetectVersion();
        bool production = options.Production ?? SPPUtils.DetectCurrentKey();

        if (options.Dump) {
          SPPUtils.DumpStore(version, production, options.DumpFilePath, options.EncrFilePath);
        } else if (options.Load) {
          SPPUtils.LoadStore(version, production, options.LoadFilePath);
        } else if (options.KMS4k) {
          KMS4k.Activate(version, production, options.ActivationId);
        } else if (options.AVMA4k) {
          AVMA4k.Activate(version, production, options.ActivationId);
        } else if (options.ZCID) {
          ZeroCID.Activate(version, production, options.ActivationId);
        } else if (options.TimerReset) {
          GracePeriodReset.Reset(version, production);
        } else if (options.DeleteUniqueId) {
          UniqueIdDelete.DeleteUniqueId(version, production, options.ActivationId);
        } else if (options.RearmReset) {
          RearmReset.Reset(version, production);
        } else if (options.InstallGenPKey) {
          GenPKeyInstall.InstallGenPKey(version, production, options.ActivationId);
        } else if (options.KMSHostCharge) {
          KMSHostCharge.Charge(version, production, options.ActivationId);
        } else if (options.TamperedFlagsDelete) {
          TamperedFlagsDelete.DeleteTamperFlags(version, production);
        } else if (options.KeyChangeLockDelete) {
          KeyChangeLockDelete.Delete(version, production);
        } else if (options.SetIIDParams) {
          SetIIDParams.SetParams(version, production, options.ActivationId, options.Algorithm.Value, options.Group, options.Serial, options.Security);
        } else if (options.Compare) {
          CompareDumps(options.CompareFile1, options.CompareFile2, version, production);
        } else {
          DisplayUsage();
        }
      } catch (Exception e) {
        #if DEBUG
        throw;
        #else
        Logger.WriteLine("Fatal error: " + e.ToString());
        Environment.Exit(1);
        #endif
      }
    }

    private static Options ParseArguments(string[] args) {
      Options options = new Options();
      for (int i = 0; i < args.Length; i++) {
        string arg = args[i].Trim().ToLowerInvariant();
        switch (arg) {
        case "/dump":
          options.Dump = true;
          if (i + 1 < args.Length && !args[i + 1].StartsWith("/")) {
            options.DumpFilePath = args[++i];
          }
          if (i + 1 < args.Length && !args[i + 1].StartsWith("/")) {
            options.EncrFilePath = args[++i];
          }
          break;
        case "/load":
          options.Load = true;
          if (i + 1 < args.Length && !args[i + 1].StartsWith("/")) {
            options.LoadFilePath = args[++i];
          }
          break;
        case "/kms4k":
          options.KMS4k = true;
          break;
        case "/avma4k":
          options.AVMA4k = true;
          break;
        case "/zcid":
          options.ZCID = true;
          break;
        case "/ver":
          options.Version = i + 1 < args.Length ? ParseVersion(args[++i]) : throw new ArgumentException("/ver requires a version argument.");
          break;
        case "/rtmr":
          options.TimerReset = true;
          break;
        case "/?":
          options.ShowHelp = true;
          break;
        case "/duid":
          options.DeleteUniqueId = true;
          break;
        case "/rrmc":
          options.RearmReset = true;
          break;
        case "/igpk":
          options.InstallGenPKey = true;
          break;
        case "/kmsc":
          options.KMSHostCharge = true;
          break;
        case "/test":
          options.Production = false;
          break;
        case "/prod":
          options.Production = true;
          break;
        case "/ctpr":
          options.TamperedFlagsDelete = true;
          break;
        case "/revl":
          options.KeyChangeLockDelete = true;
          break;
        case "/siid":
          options.SetIIDParams = true;

          if (args.Length - i - 1 < 4) throw new ArgumentException("Not enough arguments specified.");

          string algoType = args[++i];

          if (algoType == "5") {
            options.Algorithm = PKeyAlgorithm.PKEY2005;
          } else if (algoType == "9") {
            options.Algorithm = PKeyAlgorithm.PKEY2009;
          } else {
            throw new ArgumentException("Invalid key algorithm specified.");
          }

          try {
            options.Group = int.Parse(args[++i]);
            options.Serial = int.Parse(args[++i]);
            options.Security = ulong.Parse(args[++i]);
          } catch {
            throw new ArgumentException("Failed to parse key parameters.");
          }

          break;
        default:
          try {
            options.ActivationId = new Guid(arg);
          } catch (FormatException) {
            Logger.WriteLine("Argument doesn't exist or the specified activation ID is invalid.");
            options.ShowHelp = true;
          }
          break;
        case "/compare":
          options.Compare = true;
          if (i + 2 >= args.Length)
            throw new ArgumentException("/compare requires two file paths.");
          options.CompareFile1 = args[++i];
          options.CompareFile2 = args[++i];
          break;

        }
      }

      return options;
    }

    private static void DisplayUsage() {
      string exeName = typeof (Program).Namespace;
      Logger.WriteLine("Usage: " + exeName + " [/dump <filePath> (<encrFilePath>)] [/load <filePath>] [/kms4k] [/avma4k] [/zcid] [/rtmr] [/duid] [/igpk] [/kmsc] [/ctpr] [/revl] [/siid <5/9> <group> <serial> <security>] [/prod] [/test] [<activation id>] [/ver <version override>]");
      Logger.WriteLine("Options:");
      Logger.WriteLine("\t/dump <filePath> (<encrFilePath>)         Dump and decrypt the physical store to the specified path.");
      Logger.WriteLine("\t/load <filePath>                          Load and re-encrypt the physical store from the specified path.");
      Logger.WriteLine("\t/kms4k                                    Activate using KMS4k. Only supports KMS-activatable editions.");
      Logger.WriteLine("\t/avma4k                                   Activate using AVMA4k. Only supports Windows Server 2012 R2+.");
      Logger.WriteLine("\t/zcid                                     Activate using ZeroCID. Only supports phone-activatable editions.");
      Logger.WriteLine("\t/rtmr                                     Reset grace/evaluation period timers.");
      Logger.WriteLine("\t/rrmc                                     Reset the rearm count.");
      Logger.WriteLine("\t/duid                                     Delete product key Unique ID used in online key validation.");
      Logger.WriteLine("\t/igpk                                     Install auto-generated/fake product key according to the specified Activation ID");
      Logger.WriteLine("\t/kmsc                                     Reset the charged count on the local KMS server to 25. Requires an activated KMS host.");
      Logger.WriteLine("\t/ctpr                                     Remove the tamper flags that get set in the physical store when sppsvc detects an attempt to tamper with it.");
      Logger.WriteLine("\t/revl                                     Remove the key change lock in evaluation edition store.");
      Logger.WriteLine("\t/siid <5/9> <group> <serial> <security>   Set Installation ID parameters independently of installed key. 5/9 argument specifies PKEY200[5/9] key algorithm.");
      Logger.WriteLine("\t/prod                                     Use SPP production key.");
      Logger.WriteLine("\t/test                                     Use SPP test key.");
      Logger.WriteLine("\t/ver <version>                            Override the detected version. Available versions: vista, 7, 8, blue, modern.");
      Logger.WriteLine("\t<activation id>                           A specific activation ID. Useful if you want to activate specific addons like ESU.");
      Logger.WriteLine("\t/?                                        Display this help message.");
      Logger.WriteLine("\t/compare                                  Compares the dumps of a physical store.");
    }

    private static PSVersion ParseVersion(string ver) {
      switch (ver.Trim().ToLowerInvariant()) {
      case "vista":
        return PSVersion.Vista;
      case "7":
        return PSVersion.Win7;
      case "8":
        return PSVersion.Win8;
      case "blue":
        return PSVersion.WinBlue;
      case "modern":
        return PSVersion.WinModern;
      default:
        throw new ArgumentException("Invalid version specified.");
      }
    }

    private static void CompareDumps(string file1, string file2, PSVersion version, bool production) {
      byte[] data1 = System.IO.File.ReadAllBytes(file1);
      byte[] data2 = System.IO.File.ReadAllBytes(file2);

      Logger.WriteLine("=== Analyzing " + file1 + " ===");
      Logger.WriteLine("Size: 0x" + data1.Length.ToString("X"));

      Logger.WriteLine("\n=== Analyzing " + file2 + " ===");
      Logger.WriteLine("Size: 0x" + data2.Length.ToString("X"));

      Logger.WriteLine("\n=== Size Difference ===");
      Logger.WriteLine("Delta: " + (data2.Length - data1.Length) + " bytes");

      // Parse stores
      using(var ms1 = new System.IO.MemoryStream(data1))
      using(var ms2 = new System.IO.MemoryStream(data2)) {
        var reader1 = new System.IO.BinaryReader(ms1);
        var reader2 = new System.IO.BinaryReader(ms2);

        Logger.WriteLine("\n=== Searching for KMS/Volume blocks ===");

        // Search for KMS-related strings in both files
        string[] kmsStrings = new [] {
          "msft:sl/timer/VLExpiration",
          "msft:spp/kms/bind",
          "VOLUME",
          "SppBindingLicenseData",
          "msft:rm/algorithm/hwid"
        };

        foreach(string search in kmsStrings) {
          byte[] searchBytes = System.Text.Encoding.Unicode.GetBytes(search);

          int pos1 = FindBytes(data1, searchBytes);
          int pos2 = FindBytes(data2, searchBytes);

          if (pos1 >= 0 || pos2 >= 0) {
            Logger.WriteLine(string.Format("\n'{0}':", search));
            Logger.WriteLine("  " + file1 + ": " + (pos1 >= 0 ? "0x" + pos1.ToString("X") : "NOT FOUND"));
            Logger.WriteLine("  " + file2 + ": " + (pos2 >= 0 ? "0x" + pos2.ToString("X") : "NOT FOUND"));
          }
        }
      }
    }

    private static int FindBytes(byte[] haystack, byte[] needle) {
      for (int i = 0; i <= haystack.Length - needle.Length; i++) {
        bool found = true;
        for (int j = 0; j < needle.Length; j++) {
          if (haystack[i + j] != needle[j]) {
            found = false;
            break;
          }
        }
        if (found) return i;
      }
      return -1;
    }
  }
}