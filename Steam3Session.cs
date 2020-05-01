﻿using SteamKit2;
using SteamKit2.Unified.Internal;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using UnityEngine;

namespace DepotDownloader
{
    internal class Steam3Session
    {
        public class Credentials
        {
            public bool LoggedOn { get; set; }
            public ulong SessionToken { get; set; }

            public bool IsValid
            {
                get { return LoggedOn; }
            }
        }

        public ReadOnlyCollection<SteamApps.LicenseListCallback.License> Licenses
        {
            get;
            private set;
        }

        public Dictionary<uint, byte[]> AppTickets { get; private set; }
        public Dictionary<uint, ulong> AppTokens { get; private set; }
        public Dictionary<uint, byte[]> DepotKeys { get; private set; }
        public ConcurrentDictionary<string, TaskCompletionSource<SteamApps.CDNAuthTokenCallback>> CDNAuthTokens { get; private set; }
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> AppInfo { get; private set; }
        public Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo> PackageInfo { get; private set; }
        public Dictionary<string, byte[]> AppBetaPasswords { get; private set; }

        public SteamClient steamClient;
        public SteamUser steamUser;
        private SteamApps steamApps;
        private SteamUnifiedMessages.UnifiedService<IPublishedFile> steamPublishedFile;

        private CallbackManager callbacks;

        private bool authenticatedUser;
        private bool bConnected;
        private bool bConnecting;
        private bool bAborted;
        private bool bExpectingDisconnectRemote;
        private bool bDidDisconnect;
        private bool bDidReceiveLoginKey;
        private int connectionBackoff;
        private int seq; // more hack fixes
        private DateTime connectTime;

        // input
        private SteamUser.LogOnDetails logonDetails;

        // output
        private Credentials credentials;

        private static readonly TimeSpan STEAM3_TIMEOUT = TimeSpan.FromSeconds(30);

        public Steam3Session(SteamUser.LogOnDetails details)
        {
            logonDetails = details;

            authenticatedUser = details.Username != null;
            credentials = new Credentials();
            bConnected = false;
            bConnecting = false;
            bAborted = false;
            bExpectingDisconnectRemote = false;
            bDidDisconnect = false;
            bDidReceiveLoginKey = false;
            seq = 0;

            AppTickets = new Dictionary<uint, byte[]>();
            AppTokens = new Dictionary<uint, ulong>();
            DepotKeys = new Dictionary<uint, byte[]>();
            CDNAuthTokens = new ConcurrentDictionary<string, TaskCompletionSource<SteamApps.CDNAuthTokenCallback>>();
            AppInfo = new Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>();
            PackageInfo = new Dictionary<uint, SteamApps.PICSProductInfoCallback.PICSProductInfo>();
            AppBetaPasswords = new Dictionary<string, byte[]>();

            steamClient = new SteamClient();

            steamUser = steamClient.GetHandler<SteamUser>();
            steamApps = steamClient.GetHandler<SteamApps>();
            var steamUnifiedMessages = steamClient.GetHandler<SteamUnifiedMessages>();
            steamPublishedFile = steamUnifiedMessages.CreateService<IPublishedFile>();

            callbacks = new CallbackManager(steamClient);

            callbacks.Subscribe<SteamClient.ConnectedCallback>(ConnectedCallback);
            callbacks.Subscribe<SteamClient.DisconnectedCallback>(DisconnectedCallback);
            callbacks.Subscribe<SteamUser.LoggedOnCallback>(LogOnCallback);
            callbacks.Subscribe<SteamUser.SessionTokenCallback>(SessionTokenCallback);
            callbacks.Subscribe<SteamApps.LicenseListCallback>(LicenseListCallback);
            callbacks.Subscribe<SteamUser.UpdateMachineAuthCallback>(UpdateMachineAuthCallback);
            callbacks.Subscribe<SteamUser.LoginKeyCallback>(LoginKeyCallback);

            Debug.Log("Connecting to Steam3...");

            if (authenticatedUser)
            {
                FileInfo fi = new FileInfo($"{logonDetails.Username}.sentryFile");
                if (AccountSettingsStore.Instance.SentryData != null && AccountSettingsStore.Instance.SentryData.ContainsKey(logonDetails.Username))
                {
                    logonDetails.SentryFileHash = Util.SHAHash(AccountSettingsStore.Instance.SentryData[logonDetails.Username]);
                }
                else if (fi.Exists && fi.Length > 0)
                {
                    var sentryData = File.ReadAllBytes(fi.FullName);
                    logonDetails.SentryFileHash = Util.SHAHash(sentryData);
                    AccountSettingsStore.Instance.SentryData[logonDetails.Username] = sentryData;
                    AccountSettingsStore.Save();
                }
            }

            Connect();
        }

        public delegate bool WaitCondition();

        public bool WaitUntilCallback(Action submitter, WaitCondition waiter)
        {
            while (!bAborted && !waiter())
            {
                submitter();

                int seq = this.seq;
                do
                {
                    WaitForCallbacks();
                }
                while (!bAborted && seq == this.seq && !waiter());
            }

            return bAborted;
        }

        public Credentials WaitForCredentials()
        {
            if (credentials.IsValid || bAborted)
                return credentials;

            WaitUntilCallback(() => { }, () => credentials.IsValid);

            return credentials;
        }

        public void RequestAppInfo(uint appId)
        {
            if (AppInfo.ContainsKey(appId) || bAborted)
                return;

            bool completed = false;
            Action<SteamApps.PICSTokensCallback> cbMethodTokens = appTokens =>
            {
                completed = true;
                if (appTokens.AppTokensDenied.Contains(appId))
                {
                    Debug.Log($"Insufficient privileges to get access token for app {appId}");
                }

                foreach (var token_dict in appTokens.AppTokens)
                {
                    AppTokens.Add(token_dict.Key, token_dict.Value);
                }
            };

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.PICSGetAccessTokens(new List<uint>() { appId }, new List<uint>() { }), cbMethodTokens);
           }, () => completed);

            completed = false;
            Action<SteamApps.PICSProductInfoCallback> cbMethod = appInfo =>
            {
                completed = !appInfo.ResponsePending;

                foreach (var app_value in appInfo.Apps)
                {
                    var app = app_value.Value;

                    Debug.Log($"Got AppInfo for {app.ID}");
                    AppInfo.Add(app.ID, app);
                }

                foreach (var app in appInfo.UnknownApps)
                {
                    AppInfo.Add(app, null);
                }
            };

            SteamApps.PICSRequest request = new SteamApps.PICSRequest(appId);
            if (AppTokens.ContainsKey(appId))
            {
                request.AccessToken = AppTokens[appId];
                request.Public = false;
            }

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<SteamApps.PICSRequest>() { request }, new List<SteamApps.PICSRequest>() { }), cbMethod);
           }, () => completed);
        }

        public void RequestPackageInfo(IEnumerable<uint> packageIds)
        {
            List<uint> packages = packageIds.ToList();
            packages.RemoveAll(pid => PackageInfo.ContainsKey(pid));

            if (packages.Count == 0 || bAborted)
                return;

            bool completed = false;
            Action<SteamApps.PICSProductInfoCallback> cbMethod = packageInfo =>
            {
                completed = !packageInfo.ResponsePending;

                foreach (var package_value in packageInfo.Packages)
                {
                    var package = package_value.Value;
                    PackageInfo.Add(package.ID, package);
                }

                foreach (var package in packageInfo.UnknownPackages)
                {
                    PackageInfo.Add(package, null);
                }
            };

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.PICSGetProductInfo(new List<uint>(), packages), cbMethod);
           }, () => completed);
        }

        public bool RequestFreeAppLicense(uint appId)
        {
            bool success = false;
            bool completed = false;
            Action<SteamApps.FreeLicenseCallback> cbMethod = resultInfo =>
            {
                completed = true;
                success = resultInfo.GrantedApps.Contains(appId);
            };

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.RequestFreeLicense(appId), cbMethod);
           }, () => { return completed; });

            return success;
        }

        public void RequestAppTicket(uint appId)
        {
            if (AppTickets.ContainsKey(appId) || bAborted)
                return;

            if (!authenticatedUser)
            {
                AppTickets[appId] = null;
                return;
            }

            bool completed = false;
            Action<SteamApps.AppOwnershipTicketCallback> cbMethod = appTicket =>
            {
                completed = true;

                if (appTicket.Result != EResult.OK)
                {
                    Console.WriteLine($"Unable to get appticket for {appTicket.AppID}: {appTicket.Result}");
                    Abort();
                }
                else
                {
                    Console.WriteLine($"Got appticket for {appTicket.AppID}!");
                    AppTickets[appTicket.AppID] = appTicket.Ticket;
                }
            };

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.GetAppOwnershipTicket(appId), cbMethod);
           }, () => completed);
        }

        public void RequestDepotKey(uint depotId, uint appid = 0)
        {
            if (DepotKeys.ContainsKey(depotId) || bAborted)
                return;

            bool completed = false;

            Action<SteamApps.DepotKeyCallback> cbMethod = depotKey =>
            {
                completed = true;
                Console.WriteLine($"Got depot key for {depotKey.DepotID} result: {depotKey.Result}");

                if (depotKey.Result != EResult.OK)
                {
                    Abort();
                    return;
                }

                DepotKeys[depotKey.DepotID] = depotKey.DepotKey;
            };

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.GetDepotDecryptionKey(depotId, appid), cbMethod);
           }, () => completed);
        }

        public string ResolveCDNTopLevelHost(string host)
        {
            // SteamPipe CDN shares tokens with all hosts
            if (host.EndsWith(".steampipe.steamcontent.com"))
            {
                return "steampipe.steamcontent.com";
            }
            else if (host.EndsWith(".steamcontent.com"))
            {
                return "steamcontent.com";
            }

            return host;
        }

        public void RequestCDNAuthToken(uint appid, uint depotid, string host, string cdnKey)
        {
            if (CDNAuthTokens.ContainsKey(cdnKey) || bAborted)
                return;

            if (!CDNAuthTokens.TryAdd(cdnKey, new TaskCompletionSource<SteamApps.CDNAuthTokenCallback>()))
                return;

            bool completed = false;
            var timeoutDate = DateTime.Now.AddSeconds(10);
            Action<SteamApps.CDNAuthTokenCallback> cbMethod = cdnAuth =>
            {
                completed = true;
                Debug.Log($"Got CDN auth token for {host} result: {cdnAuth.Result} (expires {cdnAuth.Expiration})");

                if (cdnAuth.Result != EResult.OK)
                {
                    Abort();
                    return;
                }

                CDNAuthTokens[cdnKey].TrySetResult(cdnAuth);
            };

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.GetCDNAuthToken(appid, depotid, host), cbMethod);
           }, () => { return completed || DateTime.Now >= timeoutDate; });
        }

        public void CheckAppBetaPassword(uint appid, string password)
        {
            bool completed = false;
            Action<SteamApps.CheckAppBetaPasswordCallback> cbMethod = appPassword =>
            {
                completed = true;

                Debug.Log($"Retrieved {appPassword.BetaPasswords.Count} beta keys with result: {appPassword.Result}");

                foreach (var entry in appPassword.BetaPasswords)
                {
                    AppBetaPasswords[entry.Key] = entry.Value;
                }
            };

            WaitUntilCallback(() =>
           {
               callbacks.Subscribe(steamApps.CheckAppBetaPassword(appid, password), cbMethod);
           }, () => { return completed; });
        }

        public PublishedFileDetails GetPubfileDetails(PublishedFileID pubFile)
        {
            var pubFileRequest = new CPublishedFile_GetDetails_Request();
            pubFileRequest.publishedfileids.Add(pubFile);

            bool completed = false;
            PublishedFileDetails details = null;

            Action<SteamUnifiedMessages.ServiceMethodResponse> cbMethod = callback =>
            {
                completed = true;
                if (callback.Result == EResult.OK)
                {
                    var response = callback.GetDeserializedResponse<CPublishedFile_GetDetails_Response>();
                    details = response.publishedfiledetails[0];
                }
                else
                {
                    throw new Exception($"EResult {(int)callback.Result} ({callback.Result}) while retrieving UGC id for pubfile {pubFile}.");
                }
            };

            WaitUntilCallback(() =>
            {
                callbacks.Subscribe(steamPublishedFile.SendMessage(api => api.GetDetails(pubFileRequest)), cbMethod);
            }, () => { return completed; });

            return details;
        }

        private void Connect()
        {
            bAborted = false;
            bConnected = false;
            bConnecting = true;
            connectionBackoff = 0;
            bExpectingDisconnectRemote = false;
            bDidDisconnect = false;
            bDidReceiveLoginKey = false;
            connectTime = DateTime.Now;
            steamClient.Connect();
        }

        private void Abort(bool sendLogOff = true)
        {
            Disconnect(sendLogOff);
        }

        public void Disconnect(bool sendLogOff = true)
        {
            if (sendLogOff)
            {
                steamUser.LogOff();
            }

            steamClient.Disconnect();
            bConnected = false;
            bConnecting = false;
            bAborted = true;

            // flush callbacks until our disconnected event
            while (!bDidDisconnect)
            {
                callbacks.RunWaitAllCallbacks(TimeSpan.FromMilliseconds(100));
            }
        }

        public void TryWaitForLoginKey()
        {
            if (logonDetails.Username == null || !ContentDownloader.Config.RememberPassword) return;

            var totalWaitPeriod = DateTime.Now.AddSeconds(3);

            while (true)
            {
                DateTime now = DateTime.Now;
                if (now >= totalWaitPeriod) break;

                if (bDidReceiveLoginKey) break;

                callbacks.RunWaitAllCallbacks(TimeSpan.FromMilliseconds(100));
            }
        }

        private void WaitForCallbacks()
        {
            callbacks.RunWaitCallbacks(TimeSpan.FromSeconds(1));

            TimeSpan diff = DateTime.Now - connectTime;

            if (diff > STEAM3_TIMEOUT && !bConnected)
            {
                Debug.Log("Timeout connecting to Steam3.");
                Abort();

                return;
            }
        }

        private void ConnectedCallback(SteamClient.ConnectedCallback connected)
        {
            Debug.Log(" Done!");
            bConnecting = false;
            bConnected = true;
            if (!authenticatedUser)
            {
                Debug.Log("Logging anonymously into Steam3...");
                steamUser.LogOnAnonymous();
            }
            else
            {
                Debug.Log($"Logging '{logonDetails.Username}' into Steam3...");
                steamUser.LogOn(logonDetails);
            }
        }

        private void DisconnectedCallback(SteamClient.DisconnectedCallback disconnected)
        {
            bDidDisconnect = true;

            if (disconnected.UserInitiated || bExpectingDisconnectRemote)
            {
                Debug.Log("Disconnected from Steam");
            }
            else if (connectionBackoff >= 10)
            {
                Debug.Log("Could not connect to Steam after 10 tries");
                Abort(false);
            }
            else if (!bAborted)
            {
                if (bConnecting)
                {
                    Debug.Log("Connection to Steam failed. Trying again");
                }
                else
                {
                    Debug.Log("Lost connection to Steam. Reconnecting");
                }

                Thread.Sleep(1000 * ++connectionBackoff);
                steamClient.Connect();
            }
        }

        private void LogOnCallback(SteamUser.LoggedOnCallback loggedOn)
        {
            bool isSteamGuard = loggedOn.Result == EResult.AccountLogonDenied;
            bool is2FA = loggedOn.Result == EResult.AccountLoginDeniedNeedTwoFactor;
            bool isLoginKey = ContentDownloader.Config.RememberPassword && logonDetails.LoginKey != null && loggedOn.Result == EResult.InvalidPassword;

            if (isSteamGuard || is2FA || isLoginKey)
            {
                bExpectingDisconnectRemote = true;
                Abort(false);

                if (!isLoginKey)
                {
                    Debug.Log("This account is protected by Steam Guard.");
                }

                if (is2FA)
                {
                    Debug.Log("Please enter your 2 factor auth code from your authenticator app: ");
                    logonDetails.TwoFactorCode = Console.ReadLine();
                }
                else if (isLoginKey)
                {
                    AccountSettingsStore.Instance.LoginKeys.Remove(logonDetails.Username);
                    AccountSettingsStore.Save();

                    logonDetails.LoginKey = null;

                    if (ContentDownloader.Config.SuppliedPassword != null)
                    {
                        Debug.Log("Login key was expired. Connecting with supplied password.");
                        logonDetails.Password = ContentDownloader.Config.SuppliedPassword;
                    }
                    else
                    {
                        Debug.Log("Login key was expired. Please enter your password: ");
                        logonDetails.Password = Util.ReadPassword();
                    }
                }
                else
                {
                    Debug.Log("Please enter the authentication code sent to your email address: ");
                    logonDetails.AuthCode = Console.ReadLine();
                }

                Debug.Log("Retrying Steam3 connection...");
                Connect();

                return;
            }
            else if (loggedOn.Result == EResult.ServiceUnavailable)
            {
                Debug.Log($"Unable to login to Steam3: {loggedOn.Result}");
                Abort(false);

                return;
            }
            else if (loggedOn.Result != EResult.OK)
            {
                Debug.Log($"Unable to login to Steam3: {loggedOn.Result}");
                Abort();

                return;
            }

            Debug.Log(" Done!");

            seq++;
            credentials.LoggedOn = true;

            if (ContentDownloader.Config.CellID == 0)
            {
                Debug.Log("Using Steam3 suggested CellID: " + loggedOn.CellID);
                ContentDownloader.Config.CellID = (int)loggedOn.CellID;
            }
        }

        private void SessionTokenCallback(SteamUser.SessionTokenCallback sessionToken)
        {
            Debug.Log("Got session token!");
            credentials.SessionToken = sessionToken.SessionToken;
        }

        private void LicenseListCallback(SteamApps.LicenseListCallback licenseList)
        {
            if (licenseList.Result != EResult.OK)
            {
                Debug.Log($"Unable to get license list: {licenseList.Result} ");
                Abort();

                return;
            }

            Debug.Log($"Got {licenseList.LicenseList.Count} licenses for account!");
            Licenses = licenseList.LicenseList;
        }

        private void UpdateMachineAuthCallback(SteamUser.UpdateMachineAuthCallback machineAuth)
        {
            byte[] hash = Util.SHAHash(machineAuth.Data);
            Debug.LogFormat("Got Machine Auth: {0} {1} {2} {3} {4}", machineAuth.FileName, machineAuth.Offset, machineAuth.BytesToWrite, machineAuth.Data.Length, hash);

            AccountSettingsStore.Instance.SentryData[logonDetails.Username] = machineAuth.Data;
            AccountSettingsStore.Save();

            var authResponse = new SteamUser.MachineAuthDetails
            {
                BytesWritten = machineAuth.BytesToWrite,
                FileName = machineAuth.FileName,
                FileSize = machineAuth.BytesToWrite,
                Offset = machineAuth.Offset,

                SentryFileHash = hash, // should be the sha1 hash of the sentry file we just wrote

                OneTimePassword = machineAuth.OneTimePassword, // not sure on this one yet, since we've had no examples of steam using OTPs

                LastError = 0, // result from win32 GetLastError
                Result = EResult.OK, // if everything went okay, otherwise ~who knows~

                JobID = machineAuth.JobID, // so we respond to the correct server job
            };

            // send off our response
            steamUser.SendMachineAuthResponse(authResponse);
        }

        private void LoginKeyCallback(SteamUser.LoginKeyCallback loginKey)
        {
            Debug.Log($"Accepted new login key for account {logonDetails.Username}");

            AccountSettingsStore.Instance.LoginKeys[logonDetails.Username] = loginKey.LoginKey;
            AccountSettingsStore.Save();

            steamUser.AcceptNewLoginKey(loginKey);

            bDidReceiveLoginKey = true;
        }
    }
}