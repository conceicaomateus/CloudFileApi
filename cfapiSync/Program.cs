using Styletronix.CloudSyncProvider;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Vanara.PInvoke;
using Windows.Storage.Provider;
using static LocalNetworkServerProvider;
using static Styletronix.CloudFilterApi;
using static Styletronix.CloudFilterApi.SafeHandlers;
using static Vanara.PInvoke.CldApi;

namespace Styletronix.cfapiSync;

public class Program
{
    private static readonly int StackSize = 1024 * 512; // Buffer size for P/Invoke Call to CFExecute max 1 MB
    private static readonly int ChunkSize = 1024 * 1024 * 2; // 2MB chunkSize for File Download / Upload
    public static readonly int MinChunkSize = 4096;
    public static readonly int MaxChunkSize = int.MaxValue;

    public static async Task Main()
    {
        var clientFolderPath = @"C:\Users\mateu\ClientFolder2";
        var serverFolderPath = @"C:\Users\mateu\ServerFolder";

        //var syncProvider = new SyncProvider();

        // check if exists client folder
        if (!System.IO.Directory.Exists(clientFolderPath))
        {
            System.IO.Directory.CreateDirectory(clientFolderPath);
        }

        // check if exists server folder
        if (!System.IO.Directory.Exists(serverFolderPath))
        {
            System.IO.Directory.CreateDirectory(serverFolderPath);
        }

        await Register(clientFolderPath);

        CF_CONNECTION_KEY connectionKey;

        HRESULT ret = CfConnectSyncRoot(
                        clientFolderPath,
                        Callbacks,
                        IntPtr.Zero,
                        CF_CONNECT_FLAGS.CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO | CF_CONNECT_FLAGS.CF_CONNECT_FLAG_REQUIRE_FULL_FILE_PATH,
                        out connectionKey);

        ConnectionKey = connectionKey;

        if (ret.Succeeded)
        {
            Console.WriteLine("Connected");
        }
        else
        {
            Console.WriteLine("Connection failed!");
        }
        ret.ThrowIfFailed();

        ret = CfUpdateSyncProviderStatus(connectionKey, CF_SYNC_PROVIDER_STATUS.CF_PROVIDER_STATUS_IDLE);
        if (ret.Succeeded == false)
        {
            Console.WriteLine("Fehler bei CfUpdateSyncProviderStatus: " + ret.ToString());
        }

        //syncProvider.Start().Wait();

        Console.WriteLine("Sync finished");
        Console.ReadKey();

        //syncProvider.Stop().Wait();
    }
    private static string SyncRootId
    {
        get
        {
            var windowsUser = System.Security.Principal.WindowsIdentity.GetCurrent().User;

            return $"Optiwork!{windowsUser}!UserWebDav";
        }
    }

    private static string ClientFolder
    {
        get
        {
            return @"C:\Users\mateu\ClientFolder2";
        }
    }

    private static string ServerFolder
    {
        get
        {
            return @"C:\Users\mateu\ServerFolder";
        }
    }

    private static CF_CONNECTION_KEY connectionKey;

    private static CF_CONNECTION_KEY ConnectionKey
    {
        get
        {
            return connectionKey;
        }
        set
        {
            connectionKey = value;
        }
    }

    private static CF_CALLBACK_REGISTRATION[] Callbacks
    {
        get
        {
            var callbacks = new CF_CALLBACK_REGISTRATION[]
            {
                new() {
                    Callback = new CF_CALLBACK(GetChildren),
                    Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_FETCH_PLACEHOLDERS
                },
                new CF_CALLBACK_REGISTRATION {
                    Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS),
                    Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS
                },
                new CF_CALLBACK_REGISTRATION {
                    Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_FETCH_DATA),
                    Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_FETCH_DATA
                },
                new CF_CALLBACK_REGISTRATION {
                    Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_CANCEL_FETCH_DATA),
                    Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_CANCEL_FETCH_DATA
                },
                new CF_CALLBACK_REGISTRATION {
                    Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION),
                    Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION
                },
                new CF_CALLBACK_REGISTRATION {
                    Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION),
                    Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION
                },
                new CF_CALLBACK_REGISTRATION {
                    Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_NOTIFY_DELETE),
                    Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_NOTIFY_DELETE
                },
                new CF_CALLBACK_REGISTRATION {
                        Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION),
                        Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION
                },
                new CF_CALLBACK_REGISTRATION {
                        Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_NOTIFY_RENAME),
                        Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_NOTIFY_RENAME
                },
                new CF_CALLBACK_REGISTRATION {
                        Callback = new CF_CALLBACK(CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION),
                        Type = CF_CALLBACK_TYPE.CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION
                },
                CF_CALLBACK_REGISTRATION.CF_CALLBACK_REGISTRATION_END
            };

            return callbacks;
        }
    }

    private static string GetAssemblyGUID()
    {
        string id = "";
        foreach (object attr in System.Reflection.Assembly.GetExecutingAssembly().GetCustomAttributes(true))
        {
            if (attr is System.Runtime.InteropServices.GuidAttribute)
                id = ((System.Runtime.InteropServices.GuidAttribute)attr).Value;
        }
        return id;
    }

    private static async Task Register(string rootFolder)
    {
        if (StorageProviderSyncRootManager.IsSupported() == false)
        {
            Styletronix.Debug.WriteLine("OS not supported!", System.Diagnostics.TraceLevel.Error);
            throw new NotSupportedException();
        }

        Windows.Storage.StorageFolder path = await Windows.Storage.StorageFolder.GetFolderFromPathAsync(rootFolder);

        StorageProviderSyncRootInfo SyncRootInfo = new()
        {
            Id = SyncRootId,
            AllowPinning = true,
            DisplayNameResource = "Optiwork Client",
            HardlinkPolicy = StorageProviderHardlinkPolicy.None,
            HydrationPolicy = StorageProviderHydrationPolicy.Partial,
            HydrationPolicyModifier = StorageProviderHydrationPolicyModifier.AutoDehydrationAllowed | StorageProviderHydrationPolicyModifier.StreamingAllowed,
            InSyncPolicy = StorageProviderInSyncPolicy.FileLastWriteTime,
            Path = path,
            PopulationPolicy = StorageProviderPopulationPolicy.Full,
            ProtectionMode = StorageProviderProtectionMode.Unknown,
            ProviderId = Guid.Parse(GetAssemblyGUID()),
            Version = "1.0",
            IconResource = @"C:\WINDOWS\system32\imageres.dll,-1043",
            ShowSiblingsAsGroup = false,
            RecycleBinUri = null,
            Context = Windows.Security.Cryptography.CryptographicBuffer.ConvertStringToBinary(SyncRootId, Windows.Security.Cryptography.BinaryStringEncoding.Utf8)
        };
        SyncRootInfo.StorageProviderItemPropertyDefinitions.Add(new StorageProviderItemPropertyDefinition() { DisplayNameResource = "Beschreibung", Id = 0 });

        StorageProviderSyncRootManager.Register(SyncRootInfo);

        await Task.Delay(1000);
    }

    private static void GetChildren(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("GetChildren");

        var opInfo = CreateOPERATION_INFO(CallbackInfo, CF_OPERATION_TYPE.CF_OPERATION_TYPE_TRANSFER_PLACEHOLDERS);

        string fullPath = GetLocalFullPath(CallbackInfo);

        if (fullPath == ClientFolder)
        {
            Console.WriteLine("RootFolder");

            var folders = Directory.GetDirectories(ServerFolder);
            var files = Directory.GetFiles(ServerFolder);

            using SafePlaceHolderList infos = new();

            foreach (var folder in folders)
            {
                var folderInfo = new DirectoryInfo(folder);

                if (Directory.Exists($"{ClientFolder}\\{folderInfo.Name}"))
                    continue;

                var placeholder = new Placeholder(folderInfo);

                infos.Add(Styletronix.CloudFilterApi.CreatePlaceholderInfo(placeholder, Guid.NewGuid().ToString()));
            }

            foreach (var file in files)
            {
                var fileInfo = new FileInfo(file);
                var placeholder = new Placeholder(fileInfo);

                infos.Add(Styletronix.CloudFilterApi.CreatePlaceholderInfo(placeholder, Guid.NewGuid().ToString()));
            }

            uint total = (uint)infos.Count;
            CF_OPERATION_PARAMETERS.TRANSFERPLACEHOLDERS TpParam = new()
            {
                PlaceholderArray = infos,
                Flags = CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAGS.CF_OPERATION_TRANSFER_PLACEHOLDERS_FLAG_DISABLE_ON_DEMAND_POPULATION,
                PlaceholderCount = total,
                PlaceholderTotalCount = total,
                CompletionStatus = new NTStatus((uint)NTStatus.STATUS_SUCCESS)
            };
            CF_OPERATION_PARAMETERS cF_OPERATION_PARAMETERS = CF_OPERATION_PARAMETERS.Create(TpParam);
            CF_OPERATION_PARAMETERS opParams = cF_OPERATION_PARAMETERS;
            HRESULT executeResult = CfExecute(opInfo, ref opParams);
        }

        Console.WriteLine(fullPath);
    }

    private static void CF_CALLBACK_TYPE_FETCH_DATA(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        long length = CallbackParameters.FetchData.RequiredLength;
        long offset = CallbackParameters.FetchData.RequiredFileOffset;

        DataActions data = new()
        {
            FileOffset = offset,
            Length = length,
            NormalizedPath = CallbackInfo.NormalizedPath,
            PriorityHint = CallbackInfo.PriorityHint,
            TransferKey = CallbackInfo.TransferKey,
            Id = CallbackInfo.NormalizedPath + "!" + CallbackParameters.FetchData.RequiredFileOffset + "!" + CallbackParameters.FetchData.RequiredLength
        };

        var fetchRange = new FetchRange(data);

        FetchDataAsync(fetchRange).Wait();

        Console.WriteLine("CF_CALLBACK_TYPE_FETCH_DATA");
    }

    private static void CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_CANCEL_FETCH_PLACEHOLDERS");
    }

    private static void CF_CALLBACK_TYPE_CANCEL_FETCH_DATA(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_CANCEL_FETCH_DATA");
    }

    private static void CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION");
    }

    private static void CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION");
    }

    private static void CF_CALLBACK_TYPE_NOTIFY_DELETE(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_NOTIFY_DELETE");
    }

    private static void CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_NOTIFY_DELETE_COMPLETION");
    }

    private static void CF_CALLBACK_TYPE_NOTIFY_RENAME(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_NOTIFY_RENAME");
    }

    private static void CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION(in CF_CALLBACK_INFO CallbackInfo, in CF_CALLBACK_PARAMETERS CallbackParameters)
    {
        Console.WriteLine("CF_CALLBACK_TYPE_NOTIFY_RENAME_COMPLETION");
    }

    private static CF_OPERATION_INFO CreateOPERATION_INFO(in CF_CALLBACK_INFO CallbackInfo, CF_OPERATION_TYPE OperationType)
    {
        CF_OPERATION_INFO opInfo = new()
        {
            Type = OperationType,
            ConnectionKey = CallbackInfo.ConnectionKey,
            TransferKey = CallbackInfo.TransferKey,
            CorrelationVector = CallbackInfo.CorrelationVector,
            RequestKey = CallbackInfo.RequestKey
        };

        opInfo.StructSize = (uint)Marshal.SizeOf(opInfo);
        return opInfo;
    }

    public static CF_PLACEHOLDER_CREATE_INFO CreatePlaceholderInfo(CloudSyncProvider.Placeholder placeholder, string fileIdentity)
    {
        CF_PLACEHOLDER_CREATE_INFO cfInfo = new()
        {
            FileIdentity = Marshal.StringToCoTaskMemUni(fileIdentity),
            FileIdentityLength = (uint)(fileIdentity.Length * Marshal.SizeOf(fileIdentity[0])),

            RelativeFileName = placeholder.RelativeFileName,
            FsMetadata = new CF_FS_METADATA
            {
                FileSize = placeholder.FileSize,
                BasicInfo = CreateFileBasicInfo(placeholder)
            },
            Flags = CF_PLACEHOLDER_CREATE_FLAGS.CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC
        };

        return cfInfo;
    }

    internal static string GetLocalFullPath(in CF_CALLBACK_INFO callbackInfo)
    {
        string relativePath = GetRelativePath(callbackInfo);
        return Path.Combine(ClientFolder, relativePath);
    }

    internal static string GetRelativePath(in CF_CALLBACK_INFO callbackInfo)
    {
        var localRootFolderNormalized = ClientFolder.Remove(0, 2);

        if (callbackInfo.NormalizedPath.StartsWith(localRootFolderNormalized, StringComparison.CurrentCultureIgnoreCase))
        {
            string relativePath = callbackInfo.NormalizedPath.Remove(0, localRootFolderNormalized.Length);
            return relativePath.TrimStart(char.Parse("\\"));
        }
        return callbackInfo.NormalizedPath;
    }

    private static int GetChunkSize()
    {
        int currentChunkSize = Math.Min(ChunkSize, MaxChunkSize);
        currentChunkSize = Math.Max(currentChunkSize, MinChunkSize);
        return currentChunkSize;
    }

    private static async Task FetchDataAsync(FetchRange data)
    {
        var localRootFolderNormalized = ClientFolder.Remove(0, 2);
        string relativePath = data.NormalizedPath.Remove(0, localRootFolderNormalized.Length).TrimStart(char.Parse("\\"));
        string targetFullPath = Path.Combine(ClientFolder, relativePath);
        int currentChunkSize = GetChunkSize();
        NTStatus CompletionStatus = NTStatus.STATUS_SUCCESS;

        Styletronix.Debug.WriteLine("Fetch DataRange " + data.RangeStart + @" - " + data.RangeEnd + @" / " + relativePath, System.Diagnostics.TraceLevel.Info);

        try
        {
            CancellationToken ctx = new CancellationTokenSource().Token; // data.CancellationTokenSource.Token;
            if (ctx.IsCancellationRequested) { return; }

            CF_OPERATION_INFO opInfo = new()
            {
                Type = CF_OPERATION_TYPE.CF_OPERATION_TYPE_TRANSFER_DATA,
                ConnectionKey = ConnectionKey,
                TransferKey = data.TransferKey,
                RequestKey = new CF_REQUEST_KEY()
            };
            opInfo.StructSize = (uint)Marshal.SizeOf(opInfo);

            //if (IsExcludedFile(targetFullPath))
            //{
            //    CF_OPERATION_PARAMETERS.TRANSFERDATA TpParam = new()
            //    {
            //        Length = 1, // Length has to be greater than 0 even if transfer failed or CfExecute fails....
            //        Offset = data.RangeStart,
            //        Buffer = IntPtr.Zero,
            //        Flags = CF_OPERATION_TRANSFER_DATA_FLAGS.CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
            //        CompletionStatus = new NTStatus((uint)NtStatus.STATUS_NOT_A_CLOUD_FILE)
            //    };
            //    CF_OPERATION_PARAMETERS opParams = CF_OPERATION_PARAMETERS.Create(TpParam);
            //    Styletronix.Debug.LogResponse(CfExecute(opInfo, ref opParams));
            //    fileRangeManager.Cancel(data.NormalizedPath);
            //    return;
            //}


            //Placeholder localSimplePlaceholder = null;
            ExtendedPlaceholderState localPlaceholder = null;
            try
            {
                localPlaceholder = new(targetFullPath);

                var rootFolder = Path.Combine(ServerFolder, "teste2.docx");
                var clientFile = Path.Combine(ClientFolder, "teste2.docx");

                using IReadFileAsync fetchFile = new ReadFileAsyncInternal();
                ReadFileOpenResult openAsyncResult = await fetchFile.OpenAsync(new OpenAsyncParams()
                {
                    RelativeFileName = relativePath,
                    CancellationToken = ctx,
                    ETag = localPlaceholder?.ETag
                });

                CompletionStatus = new NTStatus((uint)openAsyncResult.Status);
                //using ExtendedPlaceholderState localPlaceholder = new(targetFullPath);

                // Compare ETag to verify Sync of cloud and local file
                if (CompletionStatus == NTStatus.STATUS_SUCCESS)
                {
                    if (openAsyncResult.Placeholder?.ETag != localPlaceholder.ETag)
                    {
                        Styletronix.Debug.WriteLine("ETag Validation FAILED: " + relativePath, System.Diagnostics.TraceLevel.Info);
                        CompletionStatus = new NTStatus((uint)Styletronix.CloudFilterApi.NtStatus.STATUS_CLOUD_FILE_NOT_IN_SYNC);
                        openAsyncResult.Message = Styletronix.CloudFilterApi.NtStatus.STATUS_CLOUD_FILE_NOT_IN_SYNC.ToString();
                    }
                }

                if (CompletionStatus != NTStatus.STATUS_SUCCESS)
                {
                    Styletronix.Debug.WriteLine("Warning: " + openAsyncResult.Message, System.Diagnostics.TraceLevel.Info);

                    CF_OPERATION_PARAMETERS.TRANSFERDATA TpParam = new()
                    {
                        Length = 1, // Length has to be greater than 0 even if transfer failed....
                        Offset = data.RangeStart,
                        Buffer = IntPtr.Zero,
                        Flags = CF_OPERATION_TRANSFER_DATA_FLAGS.CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                        CompletionStatus = CompletionStatus
                    };
                    CF_OPERATION_PARAMETERS opParams = CF_OPERATION_PARAMETERS.Create(TpParam);
                    Styletronix.Debug.LogResponse(CfExecute(opInfo, ref opParams));

                    //fileRangeManager.Cancel(data.NormalizedPath);

                    localPlaceholder.SetInSyncState(CF_IN_SYNC_STATE.CF_IN_SYNC_STATE_NOT_IN_SYNC);
                    return;
                }

                byte[] stackBuffer = new byte[StackSize];
                byte[] buffer = new byte[currentChunkSize];

                long minRangeStart = long.MaxValue;
                long totalRead = 0;

                while (data != null)
                {
                    minRangeStart = Math.Min(minRangeStart, data.RangeStart);
                    long currentRangeStart = data.RangeStart;
                    long currentRangeEnd = data.RangeEnd;

                    long currentOffset = currentRangeStart;
                    long totalLength = currentRangeEnd - currentRangeStart;

                    int readLength = (int)Math.Min(currentRangeEnd - currentOffset, currentChunkSize);

                    if (readLength > 0 && ctx.IsCancellationRequested == false)
                    {
                        ReadFileReadResult readResult = await fetchFile.ReadAsync(buffer, 0, currentOffset, readLength);
                        if (!readResult.Succeeded)
                        {
                            Styletronix.Debug.WriteLine("Error: " + readResult.Message, System.Diagnostics.TraceLevel.Error);

                            CF_OPERATION_PARAMETERS opParams = CF_OPERATION_PARAMETERS.Create(new CF_OPERATION_PARAMETERS.TRANSFERDATA
                            {
                                Length = 1, // Length has to be greater than 0 even if transfer failed....
                                Offset = data.RangeStart,
                                Buffer = IntPtr.Zero,
                                Flags = CF_OPERATION_TRANSFER_DATA_FLAGS.CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                                CompletionStatus = new NTStatus((uint)readResult.Status)
                            });
                            Styletronix.Debug.LogResponse(CfExecute(opInfo, ref opParams));

                            //fileRangeManager.Cancel(data.NormalizedPath);
                            return;
                        }
                        int dataRead = readResult.BytesRead;

                        if (data.RangeEnd == 0 || data.RangeEnd < currentOffset || data.RangeStart > currentOffset) { continue; }

                        totalRead += dataRead;
                        ReportProviderProgress(data.TransferKey, currentRangeEnd - minRangeStart, totalRead, relativePath);

                        if (dataRead < readLength && CompletionStatus == NTStatus.STATUS_SUCCESS)
                        {
                            CompletionStatus = NTStatus.STATUS_END_OF_FILE;
                        }

                        unsafe
                        {
                            fixed (byte* StackBuffer = stackBuffer)
                            {
                                int stackTransfered = 0;
                                while (stackTransfered < dataRead)
                                {
                                    if (ctx.IsCancellationRequested) { return; }

                                    int realStackSize = Math.Min(StackSize, dataRead - stackTransfered);

                                    Marshal.Copy(buffer, stackTransfered, (IntPtr)StackBuffer, realStackSize);

                                    CF_OPERATION_PARAMETERS.TRANSFERDATA TpParam = new()
                                    {
                                        Length = realStackSize,
                                        Offset = currentOffset + stackTransfered,
                                        Buffer = (IntPtr)StackBuffer,
                                        Flags = CF_OPERATION_TRANSFER_DATA_FLAGS.CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
                                        CompletionStatus = CompletionStatus
                                    };
                                    CF_OPERATION_PARAMETERS opParams = CF_OPERATION_PARAMETERS.Create(TpParam);

                                    HRESULT ret = CfExecute(opInfo, ref opParams);
                                    if (ret.Succeeded == false)
                                    {
                                        Styletronix.Debug.WriteLine(ret.ToString(), System.Diagnostics.TraceLevel.Error);
                                    }
                                    //ret.ThrowIfFailed();

                                    stackTransfered += realStackSize;
                                }
                            }
                        }

                        //fileRangeManager.RemoveRange(data.NormalizedPath, currentRangeStart, currentRangeStart + dataRead);
                    }

                    //data = fileRangeManager.TakeNext(data.NormalizedPath);
                }

                await fetchFile.CloseAsync();
            }
            finally
            {
                localPlaceholder?.Dispose();
            }


            if (ctx.IsCancellationRequested)
            {
                Styletronix.Debug.WriteLine("FETCH_DATA CANCELED", System.Diagnostics.TraceLevel.Info);
            }
            else
            {
                Styletronix.Debug.WriteLine("FETCH_DATA Completed", System.Diagnostics.TraceLevel.Verbose);
            }
        }
        catch (Exception ex)
        {
            Styletronix.Debug.WriteLine("FETCH_DATA FAILED " + ex.ToString(), System.Diagnostics.TraceLevel.Error);
            //fileRangeManager.Cancel(data.NormalizedPath);
        }
    }

    public static void ReportProviderProgress(CF_TRANSFER_KEY transferKey, long total, long completed, string relativePath)
    {
        // Report progress to System
        HRESULT ret = CfReportProviderProgress(ConnectionKey, transferKey, total, completed);
        Styletronix.Debug.LogResponse(ret);


        // Report progress to components
        try
        {
            //FileProgressEvent?.Invoke(this, new FileProgressEventArgs(relativePath, completed, total));
        }
        catch (Exception ex)
        {
            Styletronix.Debug.LogException(ex);
        }
    }

}