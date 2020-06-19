using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using JetBrains.Annotations;
using SteamKit2;
using UnityEngine;

namespace DepotDownloader
{
    public class ContentDownloaderException : Exception
    {
        public ContentDownloaderException(string value) : base(value)
        {
        }
    }

    internal static class ContentDownloader
    {
        public const uint INVALID_APP_ID = uint.MaxValue;
        public const uint INVALID_DEPOT_ID = uint.MaxValue;
        public const ulong INVALID_MANIFEST_ID = ulong.MaxValue;
        public const string DEFAULT_BRANCH = "Public";

        private const string DEFAULT_DOWNLOAD_DIR = "depots";
        private const string CONFIG_DIR = ".DepotDownloader";

        public static DownloadConfig Config = new DownloadConfig();

        private static Steam3Session steam3;
        private static Steam3Session.Credentials steam3Credentials;
        private static CDNClientPool cdnPool;
        private static readonly string STAGING_DIR = Path.Combine(CONFIG_DIR, "staging");

        public static bool IsInitialized => steam3 != null;

        public static Action<ulong, ulong> DownloadProgressChanged { get; internal set; }

        public static Action<List<DownloadedItem>> DownloadCompleted { get; internal set; }
        public static Action<List<DownloadedItem>> MultipleDownloadCompleted { get; set; } = delegate { };

        private static bool CreateDirectories(uint depotId, uint depotVersion, out string installDir)
        {
            installDir = null;
            try
            {
                if (string.IsNullOrWhiteSpace(Config.InstallDirectory))
                {
                    Directory.CreateDirectory(DEFAULT_DOWNLOAD_DIR);

                    var depotPath = Path.Combine(DEFAULT_DOWNLOAD_DIR, depotId.ToString());
                    Directory.CreateDirectory(depotPath);

                    installDir = Path.Combine(depotPath, depotVersion.ToString());
                    Directory.CreateDirectory(installDir);

                    Directory.CreateDirectory(Path.Combine(installDir, CONFIG_DIR));
                    Directory.CreateDirectory(Path.Combine(installDir, STAGING_DIR));
                }
                else
                {
                    Directory.CreateDirectory(Config.InstallDirectory);

                    installDir = Config.InstallDirectory;

                    Directory.CreateDirectory(Path.Combine(installDir, CONFIG_DIR));
                    Directory.CreateDirectory(Path.Combine(installDir, STAGING_DIR));
                }
            }
            catch
            {
                return false;
            }

            return true;
        }

        private static bool TestIsFileIncluded(string filename)
        {
            if (!Config.UsingFileList)
                return true;

            foreach (var fileListEntry in Config.FilesToDownload)
                if (fileListEntry.Equals(filename, StringComparison.OrdinalIgnoreCase))
                    return true;

            foreach (var rgx in Config.FilesToDownloadRegex)
            {
                var m = rgx.Match(filename);

                if (m.Success)
                    return true;
            }

            return false;
        }

        private static bool AccountHasAccess(uint depotId)
        {
            if (steam3 == null || steam3.steamUser.SteamID == null || steam3.Licenses == null &&
                steam3.steamUser.SteamID.AccountType != EAccountType.AnonUser)
                return false;

            var licenseQuery = steam3.steamUser.SteamID.AccountType == EAccountType.AnonUser ? new List<uint> { 17906 } : steam3.Licenses.Select(x => x.PackageID).Distinct();

            steam3.RequestPackageInfo(licenseQuery);

            foreach (var license in licenseQuery)
            {
                if (steam3.PackageInfo.TryGetValue(license, out var package) && package != null)
                {
                    if (package.KeyValues["appids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;

                    if (package.KeyValues["depotids"].Children.Any(child => child.AsUnsignedInteger() == depotId))
                        return true;
                }
            }

            return false;
        }

        internal static KeyValue GetSteam3AppSection(uint appId, EAppInfoSection section)
        {
            if (steam3?.AppInfo == null)
                return null;

            if (!steam3.AppInfo.TryGetValue(appId, out var app) || app == null)
                return null;

            var appinfo = app.KeyValues;
            string section_key;

            switch (section)
            {
                case EAppInfoSection.Common:
                    section_key = "common";
                    break;

                case EAppInfoSection.Extended:
                    section_key = "extended";
                    break;

                case EAppInfoSection.Config:
                    section_key = "config";
                    break;

                case EAppInfoSection.Depots:
                    section_key = "depots";
                    break;

                default:
                    throw new NotImplementedException();
            }

            var section_kv = appinfo.Children.Where(c => c.Name == section_key).FirstOrDefault();
            return section_kv;
        }

        private static uint GetSteam3AppBuildNumber(uint appId, string branch)
        {
            if (appId == INVALID_APP_ID)
                return 0;

            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
            var branches = depots["branches"];
            var node = branches[branch];

            if (node == KeyValue.Invalid)
                return 0;

            var buildid = node["buildid"];

            if (buildid == KeyValue.Invalid)
                return 0;

            return uint.Parse(buildid.Value);
        }

        private static ulong GetSteam3DepotManifest(uint depotId, uint appId, string branch)
        {
            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);
            var depotChild = depots[depotId.ToString()];

            if (depotChild == KeyValue.Invalid)
                return INVALID_MANIFEST_ID;

            // Shared depots can either provide manifests, or leave you relying on their parent app.
            // It seems that with the latter, "sharedinstall" will exist (and equals 2 in the one existance I know of).
            // Rather than relay on the unknown sharedinstall key, just look for manifests. Test cases: 111710, 346680.
            if (depotChild["manifests"] == KeyValue.Invalid && depotChild["depotfromapp"] != KeyValue.Invalid)
            {
                var otherAppId = depotChild["depotfromapp"].AsUnsignedInteger();
                if (otherAppId == appId)
                {
                    // This shouldn't ever happen, but ya never know with Valve. Don't infinite loop.
                    Debug.Log($"App {appId}, Depot {depotId} has depotfromapp of {otherAppId}!");
                    return INVALID_MANIFEST_ID;
                }

                steam3.RequestAppInfo(otherAppId);

                return GetSteam3DepotManifest(depotId, otherAppId, branch);
            }

            var manifests = depotChild["manifests"];
            var manifests_encrypted = depotChild["encryptedmanifests"];

            if (manifests.Children.Count == 0 && manifests_encrypted.Children.Count == 0)
                return INVALID_MANIFEST_ID;

            var node = manifests[branch];

            if (branch != "Public" && node == KeyValue.Invalid)
            {
                var node_encrypted = manifests_encrypted[branch];
                if (node_encrypted != KeyValue.Invalid)
                {
                    var password = Config.BetaPassword;
                    if (password == null)
                    {
                        Debug.Log($"Please enter the password for branch {branch}: ");
                        Config.BetaPassword = password = Console.ReadLine();
                    }

                    var encrypted_v1 = node_encrypted["encrypted_gid"];
                    var encrypted_v2 = node_encrypted["encrypted_gid_2"];

                    if (encrypted_v1 != KeyValue.Invalid)
                    {
                        var input = Util.DecodeHexString(encrypted_v1.Value);
                        var manifest_bytes = CryptoHelper.VerifyAndDecryptPassword(input, password);

                        if (manifest_bytes == null)
                        {
                            Debug.Log($"Password was invalid for branch {branch}");
                            return INVALID_MANIFEST_ID;
                        }

                        return BitConverter.ToUInt64(manifest_bytes, 0);
                    }

                    if (encrypted_v2 != KeyValue.Invalid)
                    {
                        // Submit the password to Steam now to get encryption keys
                        steam3.CheckAppBetaPassword(appId, Config.BetaPassword);

                        if (!steam3.AppBetaPasswords.ContainsKey(branch))
                        {
                            Debug.Log($"Password was invalid for branch {branch}");
                            return INVALID_MANIFEST_ID;
                        }

                        var input = Util.DecodeHexString(encrypted_v2.Value);
                        byte[] manifest_bytes;
                        try
                        {
                            manifest_bytes = CryptoHelper.SymmetricDecryptECB(input, steam3.AppBetaPasswords[branch]);
                        }
                        catch (Exception e)
                        {
                            Debug.Log($"Failed to decrypt branch {branch}: {e.Message}");
                            return INVALID_MANIFEST_ID;
                        }

                        return BitConverter.ToUInt64(manifest_bytes, 0);
                    }

                    Debug.Log($"Unhandled depot encryption for depotId {depotId}");
                    return INVALID_MANIFEST_ID;
                }

                return INVALID_MANIFEST_ID;
            }

            if (node.Value == null)
                return INVALID_MANIFEST_ID;

            return ulong.Parse(node.Value);
        }

        private static string GetAppOrDepotName(uint depotId, uint appId)
        {
            if (depotId == INVALID_DEPOT_ID)
            {
                var info = GetSteam3AppSection(appId, EAppInfoSection.Common);

                if (info == null)
                    return string.Empty;

                return info["name"].AsString();
            }

            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);

            var depotChild = depots?[depotId.ToString()];

            if (depotChild == null)
                return string.Empty;

            return depotChild["name"].AsString();
        }

        public static bool InitializeSteam3(string username, string password)
        {
            string loginKey = null;

            if (username != null && Config.RememberPassword)
                _ = AccountSettingsStore.Instance.LoginKeys.TryGetValue(username, out loginKey);

            steam3 = new Steam3Session(
                new SteamUser.LogOnDetails
                {
                    Username = username,
                    Password = loginKey == null ? password : null,
                    ShouldRememberPassword = Config.RememberPassword,
                    LoginKey = loginKey,
                    LoginID = Config.LoginID ?? 0x534B32 // "SK2"
                }
            );

            steam3Credentials = steam3.WaitForCredentials();

            if (!steam3Credentials.IsValid)
            {
                Debug.Log("Unable to get steam3 credentials.");
                return false;
            }

            cdnPool = new CDNClientPool(steam3);
            return true;
        }

        public static void ShutdownSteam3()
        {
            if (cdnPool != null)
            {
                cdnPool.Shutdown();
                cdnPool = null;
            }

            if (steam3 == null)
                return;

            steam3.TryWaitForLoginKey();
            steam3.Disconnect();
        }

        public static async Task DownloadPubfileAsync(ulong publishedFileId)
        {
            var details = steam3.GetPubfileDetails(publishedFileId);

            if (details.hcontent_file > 0)
                await DownloadAppAsync(details.consumer_appid, details.consumer_appid, details.hcontent_file,
                    DEFAULT_BRANCH, null, null, null, false, true);
            else
                Debug.Log($"Unable to locate manifest ID for published file {publishedFileId}");
        }

        public static async Task DownloadAppAsync(uint appId, uint depotId, ulong manifestId, string branch, string os,
            string arch, string language, bool lv, bool isUgc)
        {
            // Load our configuration data containing the depots currently installed
            var configPath = Config.InstallDirectory;
            if (string.IsNullOrWhiteSpace(configPath))
                configPath = DEFAULT_DOWNLOAD_DIR;

            string path = Path.Combine(configPath, CONFIG_DIR);
            if (!Directory.Exists(path))
                Directory.CreateDirectory(path);
            DepotConfigStore.LoadFromFile(Path.Combine(configPath, CONFIG_DIR, "depot.config"));

            steam3?.RequestAppInfo(appId);

            if (!AccountHasAccess(appId))
            {
                if (steam3.RequestFreeAppLicense(appId))
                    Debug.Log($"Obtained FreeOnDemand license for app {appId}");
                else
                {
                    var contentName = GetAppOrDepotName(INVALID_DEPOT_ID, appId);
                    throw new ContentDownloaderException(
                        $"App {appId} ({contentName}) is not available from this account.");
                }
            }

            var depotIDs = new List<uint>();
            var depots = GetSteam3AppSection(appId, EAppInfoSection.Depots);

            if (isUgc)
            {
                var workshopDepot = depots["workshopdepot"].AsUnsignedInteger();
                if (workshopDepot != 0)
                    depotId = workshopDepot;

                depotIDs.Add(depotId);
            }
            else
            {
                Debug.Log($"Using app branch: '{branch}'.");

                if (depots != null)
                    foreach (var depotSection in depots.Children)
                    {
                        var id = INVALID_DEPOT_ID;
                        if (depotSection.Children.Count == 0)
                            continue;

                        if (!uint.TryParse(depotSection.Name, out id))
                            continue;

                        if (depotId != INVALID_DEPOT_ID && id != depotId)
                            continue;

                        if (depotId == INVALID_DEPOT_ID)
                        {
                            var depotConfig = depotSection["config"];
                            if (depotConfig != KeyValue.Invalid)
                            {
                                if (!Config.DownloadAllPlatforms &&
                                    depotConfig["oslist"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["oslist"].Value))
                                {
                                    var oslist = depotConfig["oslist"].Value.Split(',');
                                    if (Array.IndexOf(oslist, os ?? Util.GetSteamOS()) == -1)
                                        continue;
                                }

                                if (depotConfig["osarch"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["osarch"].Value))
                                {
                                    var depotArch = depotConfig["osarch"].Value;
                                    if (depotArch != (arch ?? Util.GetSteamArch()))
                                        continue;
                                }

                                if (!Config.DownloadAllLanguages &&
                                    depotConfig["language"] != KeyValue.Invalid &&
                                    !string.IsNullOrWhiteSpace(depotConfig["language"].Value))
                                {
                                    var depotLang = depotConfig["language"].Value;
                                    if (depotLang != (language ?? "english"))
                                        continue;
                                }

                                if (!lv &&
                                    depotConfig["lowviolence"] != KeyValue.Invalid &&
                                    depotConfig["lowviolence"].AsBoolean())
                                    continue;
                            }
                        }

                        depotIDs.Add(id);
                    }

                if (depotIDs == null || depotIDs.Count == 0 && depotId == INVALID_DEPOT_ID)
                    throw new ContentDownloaderException(
                        $"Couldn't find any depots to download for app {appId}");
                if (depotIDs.Count == 0)
                    throw new ContentDownloaderException($"Depot {depotId} not listed for app {appId}");
            }

            var infos = new List<DepotDownloadInfo>();

            foreach (var depot in depotIDs)
            {
                var info = GetDepotInfo(depot, appId, manifestId, branch);
                if (info != null)
                    infos.Add(info);
            }

            try
            {
                await DownloadSteam3Async(appId, infos).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                Debug.Log($"App {appId} was not completely downloaded.");
                throw;
            }
        }

        private static DepotDownloadInfo GetDepotInfo(uint depotId, uint appId, ulong manifestId, string branch)
        {
            if (steam3 != null && appId != INVALID_APP_ID)
                steam3.RequestAppInfo(appId);

            var contentName = GetAppOrDepotName(depotId, appId);

            if (!AccountHasAccess(depotId))
            {
                Debug.Log($"Depot {depotId} ({contentName}) is not available from this account.");

                return null;
            }

            // Skip requesting an app ticket
            steam3.AppTickets[depotId] = null;

            if (manifestId == INVALID_MANIFEST_ID)
            {
                manifestId = GetSteam3DepotManifest(depotId, appId, branch);
                if (manifestId == INVALID_MANIFEST_ID && branch != "public")
                {
                    Debug.Log($"Warning: Depot {depotId} does not have branch named \"{branch}\". Trying public branch.");
                    branch = "public";
                    manifestId = GetSteam3DepotManifest(depotId, appId, branch);
                }

                if (manifestId == INVALID_MANIFEST_ID)
                {
                    Debug.Log($"Depot {depotId} ({contentName}) missing public subsection or manifest section.");
                    return null;
                }
            }

            var uVersion = GetSteam3AppBuildNumber(appId, branch);

            if (!CreateDirectories(depotId, uVersion, out var installDir))
            {
                Debug.Log("Error: Unable to create install directories!");
                return null;
            }

            steam3.RequestDepotKey(depotId, appId);
            if (!steam3.DepotKeys.ContainsKey(depotId))
            {
                Debug.Log($"No valid depot key for {depotId}, unable to download.");
                return null;
            }

            var depotKey = steam3.DepotKeys[depotId];

            var info = new DepotDownloadInfo(depotId, manifestId, installDir, contentName);
            info.depotKey = depotKey;
            return info;
        }

        private static async Task DownloadSteam3Async(uint appId, List<DepotDownloadInfo> depots)
        {
            ulong TotalBytesCompressed = 0;
            ulong TotalBytesUncompressed = 0;

            Debug.Log($"Depots to download: {depots.Count}");

            foreach (var depot in depots)
            {
                ulong DepotBytesCompressed = 0;
                ulong DepotBytesUncompressed = 0;

                Debug.Log($"Downloading depot {depot.id} - {depot.contentName}");

                var cts = new CancellationTokenSource();
                cdnPool.ExhaustedToken = cts;

                ProtoManifest oldProtoManifest = null;
                ProtoManifest newProtoManifest = null;
                var configDir = Path.Combine(depot.installDir, CONFIG_DIR);

                var lastManifestId = INVALID_MANIFEST_ID;
                DepotConfigStore.Instance.InstalledManifestIDs.TryGetValue(depot.id, out lastManifestId);

                // In case we have an early exit, this will force equiv of verifyall next run.
                DepotConfigStore.Instance.InstalledManifestIDs[depot.id] = INVALID_MANIFEST_ID;
                DepotConfigStore.Save();

                if (lastManifestId != INVALID_MANIFEST_ID)
                {
                    var oldManifestFileName = Path.Combine(configDir, $"{lastManifestId}.bin");

                    if (File.Exists(oldManifestFileName))
                    {
                        byte[] expectedChecksum;

                        try
                        {
                            expectedChecksum = File.ReadAllBytes(oldManifestFileName + ".sha");
                        }
                        catch (IOException)
                        {
                            expectedChecksum = null;
                        }

                        oldProtoManifest = ProtoManifest.LoadFromFile(oldManifestFileName, out var currentChecksum);

                        if (expectedChecksum == null || !expectedChecksum.SequenceEqual(currentChecksum))
                        {
                            // We only have to show this warning if the old manifest ID was different
                            if (lastManifestId != depot.manifestId)
                                Debug.LogWarning($"Manifest {lastManifestId} on disk did not match the expected checksum.");
                            oldProtoManifest = null;
                        }
                    }
                }

                if (lastManifestId == depot.manifestId && oldProtoManifest != null)
                {
                    newProtoManifest = oldProtoManifest;
                    Debug.Log($"Already have manifest {depot.manifestId} for depot {depot.id}.");
                }
                else
                {
                    var newManifestFileName = Path.Combine(configDir, $"{depot.manifestId}.bin");
                    // if (newManifestFileName != null)
                    {
                        byte[] expectedChecksum = null;

                        try
                        {
                            //if (File.Exists(newManifestFileName + ".sha")) // bugfix for Unity3D
                            expectedChecksum = File.ReadAllBytes(newManifestFileName + ".sha");
                        }
                        catch (IOException)
                        {
                            //expectedChecksum = null;
                        }

                        newProtoManifest = ProtoManifest.LoadFromFile(newManifestFileName, out var currentChecksum);

                        if (newProtoManifest != null &&
                            (expectedChecksum == null || !expectedChecksum.SequenceEqual(currentChecksum)))
                        {
                            Debug.Log($"Manifest {depot.manifestId} on disk did not match the expected checksum.");
                            newProtoManifest = null;
                        }
                    }

                    if (newProtoManifest != null)
                        Debug.Log($"Already have manifest {depot.manifestId} for depot {depot.id}.");
                    else
                    {
                        Debug.Log("Downloading depot manifest...");

                        DepotManifest depotManifest = null;

                        while (depotManifest == null)
                        {
                            Tuple<CDNClient.Server, string> connection = null;
                            try
                            {
                                connection =
                                    await cdnPool.GetConnectionForDepot(appId, depot.id, CancellationToken.None);

                                depotManifest = await cdnPool.CDNClient.DownloadManifestAsync(depot.id,
                                    depot.manifestId,
                                    connection.Item1, connection.Item2, depot.depotKey).ConfigureAwait(false);

                                cdnPool.ReturnConnection(connection);
                            }
                            catch (SteamKitWebRequestException e)
                            {
                                cdnPool.ReturnBrokenConnection(connection);

                                if (e.StatusCode == HttpStatusCode.Unauthorized ||
                                    e.StatusCode == HttpStatusCode.Forbidden)
                                {
                                    Debug.LogError($"Encountered 401 for depot manifest {depot.id} {depot.manifestId}. Aborting.");
                                    break;
                                }

                                Debug.LogError($"Encountered error downloading depot manifest {depot.id} {depot.manifestId}: {e.StatusCode}");
                            }
                            catch (Exception e)
                            {
                                cdnPool.ReturnBrokenConnection(connection);
                                Debug.LogError($"Encountered error downloading manifest for depot {depot.id} {depot.manifestId}: {e.Message}");
                            }
                        }

                        if (depotManifest == null)
                        {
                            Debug.LogError($"\nUnable to download manifest {depot.manifestId} for depot {depot.id}");
                            return;
                        }

                        newProtoManifest = new ProtoManifest(depotManifest, depot.manifestId);
                        newProtoManifest.SaveToFile(newManifestFileName, out var checksum);
                        File.WriteAllBytes(newManifestFileName + ".sha", checksum);

                        Debug.Log(" Done!");
                    }
                }

                newProtoManifest.Files.Sort((x, y) => string.Compare(x.FileName, y.FileName, StringComparison.Ordinal));

                if (Config.DownloadManifestOnly)
                {
                    var manifestBuilder = new StringBuilder();
                    var txtManifest = Path.Combine(depot.installDir, $"manifest_{depot.id}.txt");

                    foreach (var file in newProtoManifest.Files)
                    {
                        if (file.Flags.HasFlag(EDepotFileFlag.Directory))
                            continue;

                        manifestBuilder.Append($"{file.FileName}\n");
                    }

                    File.WriteAllText(txtManifest, manifestBuilder.ToString());
                    continue;
                }

                ulong complete_download_size = 0;
                ulong size_downloaded = 0;
                var stagingDir = Path.Combine(depot.installDir, STAGING_DIR);

                var filesAfterExclusions = newProtoManifest.Files.AsParallel()
                    .Where(f => TestIsFileIncluded(f.FileName)).ToList();

                // Pre-process
                filesAfterExclusions.ForEach(file =>
                {
                    var fileFinalPath = Path.Combine(depot.installDir, file.FileName);
                    var fileStagingPath = Path.Combine(stagingDir, file.FileName);

                    if (file.Flags.HasFlag(EDepotFileFlag.Directory))
                    {
                        Directory.CreateDirectory(fileFinalPath);
                        Directory.CreateDirectory(fileStagingPath);
                    }
                    else
                    {
                        // Some manifests don't explicitly include all necessary directories
                        Directory.CreateDirectory(Path.GetDirectoryName(fileFinalPath));
                        Directory.CreateDirectory(Path.GetDirectoryName(fileStagingPath));

                        complete_download_size += file.TotalSize;
                    }
                });

                var semaphore = new SemaphoreSlim(Config.MaxDownloads);
                var files = filesAfterExclusions.Where(f => !f.Flags.HasFlag(EDepotFileFlag.Directory)).ToArray();
                var tasks = new Task<DownloadedItem>[files.Length];
                for (var i = 0; i < files.Length; i++)
                {
                    var file = files[i];
                    var task = Task.Run(async () =>
                    {
                        byte[] arr;
                        cts.Token.ThrowIfCancellationRequested();

                        string fileFinalPath = string.Empty;
                        try
                        {
                            await semaphore.WaitAsync().ConfigureAwait(false);
                            cts.Token.ThrowIfCancellationRequested();

                            fileFinalPath = Path.Combine(depot.installDir, file.FileName);
                            var fileStagingPath = Path.Combine(stagingDir, file.FileName);

                            // This may still exist if the previous run exited before cleanup
                            if (File.Exists(fileStagingPath))
                                File.Delete(fileStagingPath);

                            FileStream fs = null;
                            List<ProtoManifest.ChunkData> neededChunks;
                            var fi = new FileInfo(fileFinalPath);
                            if (!fi.Exists)
                            {
                                // create new file. need all chunks
                                fs = File.Create(fileFinalPath);
                                fs.SetLength((long)file.TotalSize);
                                neededChunks = new List<ProtoManifest.ChunkData>(file.Chunks);
                            }
                            else
                            {
                                // open existing
                                ProtoManifest.FileData oldManifestFile = null;
                                if (oldProtoManifest != null)
                                    oldManifestFile =
                                        oldProtoManifest.Files.SingleOrDefault(f => f.FileName == file.FileName);

                                if (oldManifestFile != null)
                                {
                                    neededChunks = new List<ProtoManifest.ChunkData>();

                                    if (Config.VerifyAll || !oldManifestFile.FileHash.SequenceEqual(file.FileHash))
                                    {
                                        // we have a version of this file, but it doesn't fully match what we want

                                        var matchingChunks = new List<ChunkMatch>();

                                        foreach (var chunk in file.Chunks)
                                        {
                                            var oldChunk = oldManifestFile.Chunks.FirstOrDefault(c =>
                                                c.ChunkID.SequenceEqual(chunk.ChunkID));
                                            if (oldChunk != null)
                                                matchingChunks.Add(new ChunkMatch(oldChunk, chunk));
                                            else
                                                neededChunks.Add(chunk);
                                        }

                                        File.Move(fileFinalPath, fileStagingPath);

                                        fs = File.Open(fileFinalPath, FileMode.Create);
                                        fs.SetLength((long)file.TotalSize);

                                        using (var fsOld = File.Open(fileStagingPath, FileMode.Open))
                                            foreach (var match in matchingChunks)
                                            {
                                                fsOld.Seek((long)match.OldChunk.Offset, SeekOrigin.Begin);

                                                var tmp = new byte[match.OldChunk.UncompressedLength];
                                                fsOld.Read(tmp, 0, tmp.Length);

                                                var adler = Util.AdlerHash(tmp);
                                                if (!adler.SequenceEqual(match.OldChunk.Checksum))
                                                    neededChunks.Add(match.NewChunk);
                                                else
                                                {
                                                    fs.Seek((long)match.NewChunk.Offset, SeekOrigin.Begin);
                                                    fs.Write(tmp, 0, tmp.Length);
                                                }
                                            }

                                        File.Delete(fileStagingPath);
                                    }
                                }
                                else
                                {
                                    // No old manifest or file not in old manifest. We must validate.

                                    fs = File.Open(fileFinalPath, FileMode.Open);
                                    if ((ulong)fi.Length != file.TotalSize)
                                        fs.SetLength((long)file.TotalSize);

                                    neededChunks = Util.ValidateSteam3FileChecksums(fs,
                                        file.Chunks.OrderBy(x => x.Offset).ToArray());
                                }

                                if (!neededChunks.Any())
                                {
                                    size_downloaded += file.TotalSize;
                                    Debug.Log($"{size_downloaded / (float)complete_download_size * 100.0f,6:#00.00}% {fileFinalPath}");
                                    arr = fs.ReadFully();
                                    fs?.Dispose();
                                    return new DownloadedItem(fileFinalPath, arr);
                                }
                                else
                                    size_downloaded +=
                                        file.TotalSize - (ulong)neededChunks.Select(x => (long)x.UncompressedLength)
                                            .Sum();
                            }

                            foreach (var chunk in neededChunks)
                            {
                                if (cts.IsCancellationRequested) break;

                                var chunkID = Util.EncodeHexString(chunk.ChunkID);
                                CDNClient.DepotChunk chunkData = null;

                                while (!cts.IsCancellationRequested)
                                {
                                    Tuple<CDNClient.Server, string> connection;
                                    try
                                    {
                                        connection = await cdnPool.GetConnectionForDepot(appId, depot.id, cts.Token);
                                    }
                                    catch (OperationCanceledException)
                                    {
                                        break;
                                    }

                                    var data = new DepotManifest.ChunkData
                                    {
                                        ChunkID = chunk.ChunkID,
                                        Checksum = chunk.Checksum,
                                        Offset = chunk.Offset,
                                        CompressedLength = chunk.CompressedLength,
                                        UncompressedLength = chunk.UncompressedLength
                                    };

                                    try
                                    {
                                        chunkData = await cdnPool.CDNClient.DownloadDepotChunkAsync(depot.id, data,
                                            connection.Item1, connection.Item2, depot.depotKey).ConfigureAwait(false);
                                        cdnPool.ReturnConnection(connection);
                                        break;
                                    }
                                    catch (SteamKitWebRequestException e)
                                    {
                                        cdnPool.ReturnBrokenConnection(connection);

                                        if (e.StatusCode == HttpStatusCode.Unauthorized ||
                                            e.StatusCode == HttpStatusCode.Forbidden)
                                        {
                                            Debug.Log($"Encountered 401 for chunk {chunkID}. Aborting.");
                                            cts.Cancel();
                                            break;
                                        }

                                        Debug.Log(
                                            $"Encountered error downloading chunk {chunkID}: {e.StatusCode}");
                                    }
                                    catch (Exception e)
                                    {
                                        cdnPool.ReturnBrokenConnection(connection);
                                        Debug.Log(
                                            $"Encountered unexpected error downloading chunk {chunkID}: {e.Message}");
                                    }
                                }

                                if (chunkData == null)
                                {
                                    Debug.Log(
                                        $"Failed to find any server with chunk {chunkID} for depot {depot.id}. Aborting.");
                                    cts.Cancel();
                                }

                                // Throw the cancellation exception if requested so that this task is marked failed
                                cts.Token.ThrowIfCancellationRequested();

                                TotalBytesCompressed += chunk.CompressedLength;
                                DepotBytesCompressed += chunk.CompressedLength;
                                TotalBytesUncompressed += chunk.UncompressedLength;
                                DepotBytesUncompressed += chunk.UncompressedLength;

                                fs.Seek((long)chunk.Offset, SeekOrigin.Begin);
                                fs.Write(chunkData.Data, 0, chunkData.Data.Length);

                                DownloadProgressChanged(chunk.UncompressedLength, complete_download_size);

                                size_downloaded += chunk.UncompressedLength;
                            }

                            arr = fs.ReadFully();
                            fs.Dispose();

                            Debug.Log($"{size_downloaded / (float)complete_download_size * 100.0f,6:#00.00}% {fileFinalPath}");
                        }
                        finally
                        {
                            semaphore.Release();
                        }

                        return new DownloadedItem(fileFinalPath, arr);
                    }, cts.Token);

                    tasks[i] = task;
                }

                // TODO: Cancellable FileStream

                var arrays = await Task.WhenAll(tasks).ConfigureAwait(false);

                DepotConfigStore.Instance.InstalledManifestIDs[depot.id] = depot.manifestId;
                DepotConfigStore.Save();

                Debug.Log(
                    $"Depot {depot.id} - Downloaded {DepotBytesCompressed} bytes ({DepotBytesUncompressed} bytes uncompressed)");

                Debug.Assert(arrays.Length == 1); // TODO: This works only for single file download
                DownloadCompleted(null); // TODO
                MultipleDownloadCompleted(arrays.ToList());
            }

            Debug.Log(
                $"Total downloaded: {TotalBytesCompressed} bytes ({TotalBytesUncompressed} bytes uncompressed) from {depots.Count} depots");
        }

        private static byte[] ReadFully(this Stream input)
        {
            using (var ms = new MemoryStream())
            {
                input.CopyTo(ms);
                return ms.ToArray();
            }
        }

        private sealed class DepotDownloadInfo
        {
            public byte[] depotKey;

            public DepotDownloadInfo(uint depotid, ulong manifestId, string installDir, string contentName)
            {
                id = depotid;
                this.manifestId = manifestId;
                this.installDir = installDir;
                this.contentName = contentName;
            }

            public uint id { get; }
            public string installDir { get; }
            public string contentName { get; }

            public ulong manifestId { get; }
        }

        private class ChunkMatch
        {
            public ChunkMatch(ProtoManifest.ChunkData oldChunk, ProtoManifest.ChunkData newChunk)
            {
                OldChunk = oldChunk;
                NewChunk = newChunk;
            }

            public ProtoManifest.ChunkData OldChunk { get; }
            public ProtoManifest.ChunkData NewChunk { get; }
        }

        public class DownloadedItem
        {
            public string Path { get; }
            public byte[] Data { get; }

            private DownloadedItem()
            {
            }

            public DownloadedItem(string path, byte[] data)
            {
                Path = path;
                Data = data;
            }
        }
    }
}