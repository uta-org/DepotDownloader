using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.IO.IsolatedStorage;
using ProtoBuf;

namespace DepotDownloader
{
    [ProtoContract]
    internal class AccountSettingsStore
    {
        public static AccountSettingsStore Instance;
        private static readonly IsolatedStorageFile IsolatedStorage = IsolatedStorageFile.GetUserStoreForAssembly();

        private string FileName;

        private AccountSettingsStore()
        {
            SentryData = new Dictionary<string, byte[]>();
            ContentServerPenalty = new ConcurrentDictionary<string, int>();
            LoginKeys = new Dictionary<string, string>();
        }

        [ProtoMember(1, IsRequired = false)] public Dictionary<string, byte[]> SentryData { get; }

        [ProtoMember(2, IsRequired = false)] public ConcurrentDictionary<string, int> ContentServerPenalty { get; }

        [ProtoMember(3, IsRequired = false)] public Dictionary<string, string> LoginKeys { get; }

        private static bool Loaded => Instance != null;

        public static void LoadFromFile(string filename)
        {
            if (Loaded)
                throw new Exception("Config already loaded");

            if (IsolatedStorage.FileExists(filename))
                try
                {
                    using (var fs = IsolatedStorage.OpenFile(filename, FileMode.Open, FileAccess.Read))
                    using (var ds = new DeflateStream(fs, CompressionMode.Decompress))
                        Instance = Serializer.Deserialize<AccountSettingsStore>(ds);
                }
                catch (IOException ex)
                {
                    Console.WriteLine("Failed to load account settings: {0}", ex.Message);
                    Instance = new AccountSettingsStore();
                }
            else
                Instance = new AccountSettingsStore();

            Instance.FileName = filename;
        }

        public static void Save()
        {
            if (!Loaded)
                throw new Exception("Saved config before loading");

            try
            {
                using (var fs = IsolatedStorage.OpenFile(Instance.FileName, FileMode.Create, FileAccess.Write))
                using (var ds = new DeflateStream(fs, CompressionMode.Compress))
                    Serializer.Serialize(ds, Instance);
            }
            catch (IOException ex)
            {
                Console.WriteLine("Failed to save account settings: {0}", ex.Message);
            }
        }
    }
}