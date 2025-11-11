namespace LibTSforge.SPP
{
    using Microsoft.Win32;
    using System;
    using System.IO;
    using System.Linq;
    using System.ServiceProcess;
    using Crypto;
    using PhysicalStore;
    using TokenStore;

    public static class SPPUtils
    {
        public static void KillSPP(PSVersion version)
        {
            ServiceController sc;

            string svcName = "sppsvc";

            try
            {
                sc = new ServiceController(svcName);

                if (sc.Status == ServiceControllerStatus.Stopped)
                    return;
            }
            catch (InvalidOperationException ex)
            {
                throw new InvalidOperationException(string.Format("Unable to access {0}: ", svcName) + ex.Message);
            }

            Logger.WriteLine(string.Format("Stopping {0}...", svcName));

            bool stopped = false;

            for (int i = 0; stopped == false && i < 1080; i++)
            {
                try
                {
                    if (sc.Status != ServiceControllerStatus.StopPending)
                        sc.Stop();

                    sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromMilliseconds(500));
                }
                catch (System.ServiceProcess.TimeoutException)
                {
                    continue;
                }
                catch (InvalidOperationException ex)
                {
                    Logger.WriteLine("Warning: Stopping sppsvc failed, retrying. Details: " + ex.Message);
                    System.Threading.Thread.Sleep(500);
                    continue;
                }

                stopped = true;
            }

            if (!stopped)
                throw new System.TimeoutException(string.Format("Failed to stop {0}", svcName));

            Logger.WriteLine(string.Format("{0} stopped successfully.", svcName));

            if (version == PSVersion.Vista && SPSys.IsSpSysRunning())
            {
                Logger.WriteLine("Unloading spsys...");

                int status = SPSys.ControlSpSys(false);

                if (status < 0)
                {
                    throw new IOException("Failed to unload spsys");
                }

                Logger.WriteLine("spsys unloaded successfully.");
            }
        }

        public static void RestartSPP(PSVersion version)
        {
            if (version == PSVersion.Vista)
            {
                ServiceController sc;

                try
                {
                    sc = new ServiceController("sppsvc");

                    if (sc.Status == ServiceControllerStatus.Running)
                        return;
                }
                catch (InvalidOperationException ex)
                {
                    throw new InvalidOperationException("Unable to access sppsvc: " + ex.Message);
                }

                Logger.WriteLine("Starting sppsvc...");

                bool started = false;

                for (int i = 0; started == false && i < 360; i++)
                {
                    try
                    {
                        if (sc.Status != ServiceControllerStatus.StartPending)
                            sc.Start();

                        sc.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromMilliseconds(500));
                    }
                    catch (System.ServiceProcess.TimeoutException)
                    {
                        continue;
                    }
                    catch (InvalidOperationException ex)
                    {
                        Logger.WriteLine("Warning: Starting sppsvc failed, retrying. Details: " + ex.Message);
                        System.Threading.Thread.Sleep(500);
                        continue;
                    }

                    started = true;
                }

                if (!started)
                    throw new System.TimeoutException("Failed to start sppsvc");

                Logger.WriteLine("sppsvc started successfully.");
            }

            SLApi.RefreshLicenseStatus();
        }

        public static bool DetectCurrentKey()
        {
            SLApi.RefreshLicenseStatus();

            using (RegistryKey wpaKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\WPA"))
            {
                foreach (string subKey in wpaKey.GetSubKeyNames())
                {
                    if (subKey.StartsWith("8DEC0AF1"))
                    {
                        return subKey.Contains("P");
                    }
                }
            }

            throw new FileNotFoundException("Failed to autodetect key type, specify physical store key with /prod or /test arguments.");
        }

        public static string GetPSPath(PSVersion version)
        {
            switch (version)
            {
                case PSVersion.Vista:
                case PSVersion.Win7:
                    return Directory.GetFiles(
                        Environment.GetFolderPath(Environment.SpecialFolder.System),
                        "7B296FB0-376B-497e-B012-9C450E1B7327-*.C7483456-A289-439d-8115-601632D005A0")
                    .FirstOrDefault() ?? "";
                default:
                    string psDir = Environment.ExpandEnvironmentVariables(
                        (string)Registry.GetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
                            "TokenStore",
                            ""
                        )
                    );
                    string psPath = Path.Combine(psDir, "data.dat");

                    if (string.IsNullOrEmpty(psDir) || !File.Exists(psPath))
                    {
                        string[] psDirs =
                        {
                            @"spp\store",
                            @"spp\store\2.0",
                            @"spp\store_test",
                            @"spp\store_test\2.0"
                        };

                        foreach (string dir in psDirs)
                        {
                            psPath = Path.Combine(
                                Path.Combine(
                                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                                    dir
                                ),
                                "data.dat"
                            );

                            if (File.Exists(psPath)) return psPath;
                        }
                    } 
                    else
                    {
                        return psPath;
                    }

                    throw new FileNotFoundException("Failed to locate physical store.");
            }
        }

        public static string GetTokensPath(PSVersion version)
        {
            switch (version)
            {
                case PSVersion.Vista:
                    return Path.Combine(
                        Environment.ExpandEnvironmentVariables("%WINDIR%"),
                        @"ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareLicensing\tokens.dat"
                    );
                case PSVersion.Win7:
                    return Path.Combine(
                        Environment.ExpandEnvironmentVariables("%WINDIR%"),
                        @"ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\SoftwareProtectionPlatform\tokens.dat"
                    );
                default:
                    string tokDir = Environment.ExpandEnvironmentVariables(
                        (string)Registry.GetValue(
                            @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform",
                            "TokenStore",
                            ""
                        )
                    );
                    string tokPath = Path.Combine(tokDir, "tokens.dat");

                    if (string.IsNullOrEmpty(tokDir) || !File.Exists(tokPath))
                    {
                        string[] tokDirs =
                        {
                            @"spp\store",
                            @"spp\store\2.0",
                            @"spp\store_test",
                            @"spp\store_test\2.0"
                        };

                        foreach (string dir in tokDirs)
                        {
                            tokPath = Path.Combine(
                                Path.Combine(
                                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                                    dir
                                ),
                                "tokens.dat"
                            );

                            if (File.Exists(tokPath)) return tokPath;
                        }
                    }
                    else
                    {
                        return tokPath;
                    }

                    throw new FileNotFoundException("Failed to locate token store.");
            }
        }

        public static IPhysicalStore GetStore(PSVersion version, bool production)
        {
            string psPath = GetPSPath(version);

            switch (version)
            {
                case PSVersion.Vista:
                    return new PhysicalStoreVista(psPath, production);
                case PSVersion.Win7:
                    return new PhysicalStoreWin7(psPath, production);
                default:
                    return new PhysicalStoreModern(psPath, production, version);
            }
        }

        public static ITokenStore GetTokenStore(PSVersion version)
        {
            string tokPath = GetTokensPath(version);

            return new TokenStoreModern(tokPath);
        }

        public static void DumpStore(PSVersion version, bool production, string filePath, string encrFilePath)
        {
            bool manageSpp = false;

            if (encrFilePath == null)
            {
                encrFilePath = GetPSPath(version);
                manageSpp = true;
                KillSPP(version);
            }

            if (string.IsNullOrEmpty(encrFilePath) || !File.Exists(encrFilePath))
            {
                throw new FileNotFoundException("Store does not exist at expected path '" + encrFilePath + "'.");
            }

            try
            {
                using (FileStream fs = File.Open(encrFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    byte[] encrData = fs.ReadAllBytes();
                    File.WriteAllBytes(filePath, PhysStoreCrypto.DecryptPhysicalStore(encrData, production, version));
                }
                Logger.WriteLine("Store dumped successfully to '" + filePath + "'.");
            }
            finally
            {
                if (manageSpp)
                {
                    RestartSPP(version);
                }
            }
        }

        public static void LoadStore(PSVersion version, bool production, string filePath)
        {
            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                throw new FileNotFoundException("Store file '" + filePath + "' does not exist.");
            }

            KillSPP(version);

            using (IPhysicalStore store = GetStore(version, production))
            {
                store.WriteRaw(File.ReadAllBytes(filePath));
            }

            RestartSPP(version);

            Logger.WriteLine("Loaded store file successfully.");
        }
    }
}
