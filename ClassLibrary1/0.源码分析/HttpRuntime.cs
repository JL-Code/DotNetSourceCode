using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Web._0.源码分析
{
    public sealed class HttpRuntime
    {

        internal const string codegenDirName = "Temporary ASP.NET Files";
        internal const string profileFileName = "profileoptimization.prof";

        private static HttpRuntime _theRuntime;   // single instance of the class
        internal static byte[] s_autogenKeys = new byte[1024];

        //
        // Names of special ASP.NET directories
        //

        internal const string BinDirectoryName = "bin";
        internal const string CodeDirectoryName = "App_Code";
        internal const string WebRefDirectoryName = "App_WebReferences";
        internal const string ResourcesDirectoryName = "App_GlobalResources";
        internal const string LocalResourcesDirectoryName = "App_LocalResources";
        internal const string DataDirectoryName = "App_Data";
        internal const string ThemesDirectoryName = "App_Themes";
        internal const string GlobalThemesDirectoryName = "Themes";
        internal const string BrowsersDirectoryName = "App_Browsers";

        private static string DirectorySeparatorString = new string(Path.DirectorySeparatorChar, 1);
        private static string DoubleDirectorySeparatorString = new string(Path.DirectorySeparatorChar, 2);
        private static char[] s_InvalidPhysicalPathChars = { '/', '?', '*', '<', '>', '|', '"' };



#if OLD
        // For s_forbiddenDirs and s_forbiddenDirsConstant, see
        // ndll.h, and RestrictIISFolders in regiis.cxx

        internal static string[]    s_forbiddenDirs =   {
                                        BinDirectoryName,
                                        CodeDirectoryName,
                                        DataDirectoryName,
                                        ResourcesDirectoryName,
                                        WebRefDirectoryName,
                                    };

        internal static Int32[]     s_forbiddenDirsConstant = {
                                        UnsafeNativeMethods.RESTRICT_BIN,
                                        UnsafeNativeMethods.RESTRICT_CODE,
                                        UnsafeNativeMethods.RESTRICT_DATA,
                                        UnsafeNativeMethods.RESTRICT_RESOURCES,
                                        UnsafeNativeMethods.RESTRICT_WEBREFERENCES,
                                    };
#endif

        static HttpRuntime()
        {
            AddAppDomainTraceMessage("*HttpRuntime::cctor");

            StaticInit();

            _theRuntime = new HttpRuntime();

            _theRuntime.Init();

            AddAppDomainTraceMessage("HttpRuntime::cctor*");
        }

        private void Init()
        {
            try
            {
#if !FEATURE_PAL
                if (Environment.OSVersion.Platform != PlatformID.Win32NT)
                    throw new PlatformNotSupportedException(SR.GetString(SR.RequiresNT));
#else // !FEATURE_PAL
                // ROTORTODO
                // Do nothing: FEATURE_PAL environment will always support ASP.NET hosting
#endif // !FEATURE_PAL

                _profiler = new Profiler();
                _timeoutManager = new RequestTimeoutManager();
                _wpUserId = GetCurrentUserName();

                _requestNotificationCompletionCallback = new AsyncCallback(this.OnRequestNotificationCompletion);
                _handlerCompletionCallback = new AsyncCallback(this.OnHandlerCompletion);
                _asyncEndOfSendCallback = new HttpWorkerRequest.EndOfSendNotification(this.EndOfSendCallback);
                _appDomainUnloadallback = new WaitCallback(this.ReleaseResourcesAndUnloadAppDomain);


                // appdomain values
                if (GetAppDomainString(".appDomain") != null)
                {

                    Debug.Assert(HostingEnvironment.IsHosted);

                    _appDomainAppId = GetAppDomainString(".appId");
                    _appDomainAppPath = GetAppDomainString(".appPath");
                    _appDomainAppVPath = VirtualPath.CreateNonRelativeTrailingSlash(GetAppDomainString(".appVPath"));
                    _appDomainId = GetAppDomainString(".domainId");

                    _isOnUNCShare = StringUtil.StringStartsWith(_appDomainAppPath, "\\\\");

                    // init perf counters for this appdomain
                    PerfCounters.Open(_appDomainAppId);
                }
                else
                {
                    Debug.Assert(!HostingEnvironment.IsHosted);
                }

                // _appDomainAppPath should be set before file change notifications are initialized
                // DevDiv 248126: Check httpRuntime fcnMode first before we use the registry key
                _fcm = new FileChangesMonitor(HostingEnvironment.FcnMode);
            }
            catch (Exception e)
            {
                // remember static initalization error
                InitializationException = e;
            }
        }

        private void SetUpDataDirectory()
        {

            // Set the DataDirectory (see VSWhidbey 226834) with permission (DevDiv 29614)
            string dataDirectory = Path.Combine(_appDomainAppPath, DataDirectoryName);
            AppDomain.CurrentDomain.SetData("DataDirectory", dataDirectory,
                    new FileIOPermission(FileIOPermissionAccess.PathDiscovery, dataDirectory));
        }

        private void DisposeAppDomainShutdownTimer()
        {
            Timer timer = _appDomainShutdownTimer;
            if (timer != null && Interlocked.CompareExchange(ref _appDomainShutdownTimer, null, timer) == timer)
            {
                timer.Dispose();
            }
        }

        private void AppDomainShutdownTimerCallback(Object state)
        {
            try
            {
                DisposeAppDomainShutdownTimer();
                ShutdownAppDomain(ApplicationShutdownReason.InitializationError, "Initialization Error");
            }
            catch { } // ignore exceptions
        }

        /*
         * Restart the AppDomain in 10 seconds
         */
        private void StartAppDomainShutdownTimer()
        {
            if (_appDomainShutdownTimer == null && !_shutdownInProgress)
            {
                lock (this)
                {
                    if (_appDomainShutdownTimer == null && !_shutdownInProgress)
                    {
                        _appDomainShutdownTimer = new Timer(
                            new TimerCallback(this.AppDomainShutdownTimerCallback),
                            null,
                            10 * 1000,
                            0);
                    }
                }
            }
        }


        internal static Exception InitializationException
        {
            get
            {
                return _theRuntime._initializationError;
            }

            // The exception is "cached" for 10 seconds, then the AppDomain is restarted.
            set
            {
                _theRuntime._initializationError = value;
                // In v2.0, we shutdown immediately if hostingInitFailed...so we don't need the timer
                if (!HostingInitFailed)
                {
                    _theRuntime.StartAppDomainShutdownTimer();
                }
            }
        }

        internal static bool HostingInitFailed
        {
            get
            {
                return _theRuntime._hostingInitFailed;
            }
        }


        /*
         * Initialization on first request (context available)
         */
        private void FirstRequestInit(HttpContext context)
        {
            Exception error = null;

            if (InitializationException == null && _appDomainId != null)
            {
#if DBG
                HttpContext.SetDebugAssertOnAccessToCurrent(true);
#endif
                try
                {
                    using (new ApplicationImpersonationContext())
                    {
                        // Is this necessary?  See InitHttpConfiguration
                        CultureInfo savedCulture = Thread.CurrentThread.CurrentCulture;
                        CultureInfo savedUICulture = Thread.CurrentThread.CurrentUICulture;

                        try
                        {
                            // Ensure config system is initialized
                            InitHttpConfiguration(); // be sure config system is set

                            // Check if applicaton is enabled
                            CheckApplicationEnabled();

                            // Check access to temp compilation directory (under hosting identity)
                            CheckAccessToTempDirectory();

                            // Initialize health monitoring
                            InitializeHealthMonitoring();

                            // Init request queue (after reading config)
                            InitRequestQueue();

                            // configure the profiler according to config
                            InitTrace(context);

                            // Start heatbeat for Web Event Health Monitoring
                            HealthMonitoringManager.StartHealthMonitoringHeartbeat();

                            // Remove read and browse access of the bin directory
                            RestrictIISFolders(context);

                            // Preload all assemblies from bin (only if required).  ASURT 114486
                            PreloadAssembliesFromBin();

                            // Decide whether or not to encode headers.  VsWhidbey 257154
                            InitHeaderEncoding();

                            // Force the current encoder + validator to load so that there's a deterministic
                            // place (here) for an exception to occur if there's a load error
                            HttpEncoder.InitializeOnFirstRequest();
                            RequestValidator.InitializeOnFirstRequest();

                            if (context.WorkerRequest is ISAPIWorkerRequestOutOfProc)
                            {
                                // Make sure that the <processModel> section has no errors
                                ProcessModelSection processModel = RuntimeConfig.GetMachineConfig().ProcessModel;
                            }
                        }
                        finally
                        {
                            Thread.CurrentThread.CurrentUICulture = savedUICulture;
                            SetCurrentThreadCultureWithAssert(savedCulture);
                        }
                    }
                }
                catch (ConfigurationException e)
                {
                    error = e;
                }
                catch (Exception e)
                {
                    // remember second-phase initialization error
                    error = new HttpException(SR.GetString(SR.XSP_init_error, e.Message), e);
                }
                finally
                {
#if DBG
                    HttpContext.SetDebugAssertOnAccessToCurrent(false);
#endif
                }
            }

            if (InitializationException != null)
            {
                // throw cached exception.  We need to wrap it in a new exception, otherwise
                // we lose the original stack.
                throw new HttpException(InitializationException.Message, InitializationException);
            }
            else if (error != null)
            {
                InitializationException = error;
                // throw new exception
                throw error;
            }

            AddAppDomainTraceMessage("FirstRequestInit");
        }


        internal static void SetCurrentThreadCultureWithAssert(CultureInfo cultureInfo)
        {
            Thread.CurrentThread.CurrentCulture = cultureInfo;
        }

        private void EnsureFirstRequestInit(HttpContext context)
        {
            if (_beforeFirstRequest)
            {
                lock (this)
                {
                    if (_beforeFirstRequest)
                    {
                        _firstRequestStartTime = DateTime.UtcNow;
                        FirstRequestInit(context);
                        _beforeFirstRequest = false;
                        context.FirstRequest = true;
                    }
                }
            }
        }

      

    
     

        private void InitRequestQueue()
        {
            RuntimeConfig config = RuntimeConfig.GetAppConfig();
            HttpRuntimeSection runtimeConfig = config.HttpRuntime;
            ProcessModelSection processConfig = config.ProcessModel;

            if (processConfig.AutoConfig)
            {
                _requestQueue = new RequestQueue(
                    88 * processConfig.CpuCount,
                    76 * processConfig.CpuCount,
                    runtimeConfig.AppRequestQueueLimit,
                    processConfig.ClientConnectedCheck);
            }
            else
            {

                // Configuration section handlers cannot validate values based on values
                // in other configuration sections, so we validate minFreeThreads and
                // minLocalRequestFreeThreads here.
                int maxThreads = (processConfig.MaxWorkerThreadsTimesCpuCount < processConfig.MaxIoThreadsTimesCpuCount) ? processConfig.MaxWorkerThreadsTimesCpuCount : processConfig.MaxIoThreadsTimesCpuCount;
                // validate minFreeThreads
                if (runtimeConfig.MinFreeThreads >= maxThreads)
                {
                    if (runtimeConfig.ElementInformation.Properties["minFreeThreads"].LineNumber == 0)
                    {
                        if (processConfig.ElementInformation.Properties["maxWorkerThreads"].LineNumber != 0)
                        {
                            throw new ConfigurationErrorsException(SR.GetString(SR.Thread_pool_limit_must_be_greater_than_minFreeThreads, runtimeConfig.MinFreeThreads.ToString(CultureInfo.InvariantCulture)),
                                                                   processConfig.ElementInformation.Properties["maxWorkerThreads"].Source,
                                                                   processConfig.ElementInformation.Properties["maxWorkerThreads"].LineNumber);
                        }
                        else
                        {
                            throw new ConfigurationErrorsException(SR.GetString(SR.Thread_pool_limit_must_be_greater_than_minFreeThreads, runtimeConfig.MinFreeThreads.ToString(CultureInfo.InvariantCulture)),
                                                                   processConfig.ElementInformation.Properties["maxIoThreads"].Source,
                                                                   processConfig.ElementInformation.Properties["maxIoThreads"].LineNumber);
                        }
                    }
                    else
                    {
                        throw new ConfigurationErrorsException(SR.GetString(SR.Min_free_threads_must_be_under_thread_pool_limits, maxThreads.ToString(CultureInfo.InvariantCulture)),
                                                               runtimeConfig.ElementInformation.Properties["minFreeThreads"].Source,
                                                               runtimeConfig.ElementInformation.Properties["minFreeThreads"].LineNumber);
                    }
                }
                // validate minLocalRequestFreeThreads
                if (runtimeConfig.MinLocalRequestFreeThreads > runtimeConfig.MinFreeThreads)
                {
                    if (runtimeConfig.ElementInformation.Properties["minLocalRequestFreeThreads"].LineNumber == 0)
                    {
                        throw new ConfigurationErrorsException(SR.GetString(SR.Local_free_threads_cannot_exceed_free_threads),
                                                               processConfig.ElementInformation.Properties["minFreeThreads"].Source,
                                                               processConfig.ElementInformation.Properties["minFreeThreads"].LineNumber);
                    }
                    else
                    {
                        throw new ConfigurationErrorsException(SR.GetString(SR.Local_free_threads_cannot_exceed_free_threads),
                                                               runtimeConfig.ElementInformation.Properties["minLocalRequestFreeThreads"].Source,
                                                               runtimeConfig.ElementInformation.Properties["minLocalRequestFreeThreads"].LineNumber);
                    }
                }

                _requestQueue = new RequestQueue(
                    runtimeConfig.MinFreeThreads,
                    runtimeConfig.MinLocalRequestFreeThreads,
                    runtimeConfig.AppRequestQueueLimit,
                    processConfig.ClientConnectedCheck);
            }
        }

        private void InitApartmentThreading()
        {
            HttpRuntimeSection runtimeConfig = RuntimeConfig.GetAppConfig().HttpRuntime;

            if (runtimeConfig != null)
            {
                _apartmentThreading = runtimeConfig.ApartmentThreading;
            }
            else
            {
                _apartmentThreading = false;
            }
        }

        private void InitTrace(HttpContext context)
        {
            TraceSection traceConfig = RuntimeConfig.GetAppConfig().Trace;

            Profile.RequestsToProfile = traceConfig.RequestLimit;
            Profile.PageOutput = traceConfig.PageOutput;
            Profile.OutputMode = TraceMode.SortByTime;
            if (traceConfig.TraceMode == TraceDisplayMode.SortByCategory)
                Profile.OutputMode = TraceMode.SortByCategory;

            Profile.LocalOnly = traceConfig.LocalOnly;
            Profile.IsEnabled = traceConfig.Enabled;
            Profile.MostRecent = traceConfig.MostRecent;
            Profile.Reset();

            // the first request's context is created before InitTrace, so
            // we need to set this manually. (ASURT 93730)
            context.TraceIsEnabled = traceConfig.Enabled;
            TraceContext.SetWriteToDiagnosticsTrace(traceConfig.WriteToDiagnosticsTrace);
        }


        /*
         * Pre-load all the bin assemblies if we're impersonated.  This way, if user code
         * calls Assembly.Load while impersonated, the assembly will already be loaded, and
         * we won't fail due to lack of permissions on the codegen dir (see ASURT 114486)
         */
        [PermissionSet(SecurityAction.Assert, Unrestricted = true)]
        private void PreloadAssembliesFromBin()
        {
            bool appClientImpersonationEnabled = false;

            if (!_isOnUNCShare)
            {
                // if not on UNC share check if config has impersonation enabled (without userName)
                IdentitySection c = RuntimeConfig.GetAppConfig().Identity;
                if (c.Impersonate && c.ImpersonateToken == IntPtr.Zero)
                    appClientImpersonationEnabled = true;
            }

            if (!appClientImpersonationEnabled)
                return;

            // Get the path to the bin directory
            string binPath = HttpRuntime.BinDirectoryInternal;

            DirectoryInfo binPathDirectory = new DirectoryInfo(binPath);

            if (!binPathDirectory.Exists)
                return;

            PreloadAssembliesFromBinRecursive(binPathDirectory);
        }

        private void PreloadAssembliesFromBinRecursive(DirectoryInfo dirInfo)
        {

            FileInfo[] binDlls = dirInfo.GetFiles("*.dll");

            // Pre-load all the assemblies, ignoring all exceptions
            foreach (FileInfo fi in binDlls)
            {
                try { Assembly.Load(System.Web.UI.Util.GetAssemblyNameFromFileName(fi.Name)); }
                catch (FileNotFoundException)
                {
                    // If Load failed, try LoadFrom (VSWhidbey 493725)
                    try { Assembly.LoadFrom(fi.FullName); }
                    catch { }
                }
                catch { }
            }

            // Recurse on the subdirectories
            DirectoryInfo[] subDirs = dirInfo.GetDirectories();
            foreach (DirectoryInfo di in subDirs)
            {
                PreloadAssembliesFromBinRecursive(di);
            }
        }

        private void SetAutoConfigLimits(ProcessModelSection pmConfig)
        {
            // check if the current limits are ok
            int workerMax, ioMax;
            ThreadPool.GetMaxThreads(out workerMax, out ioMax);

            // only set if different
            if (pmConfig.DefaultMaxWorkerThreadsForAutoConfig != workerMax || pmConfig.DefaultMaxIoThreadsForAutoConfig != ioMax)
            {
                Debug.Trace("ThreadPool", "SetThreadLimit: from " + workerMax + "," + ioMax + " to " + pmConfig.DefaultMaxWorkerThreadsForAutoConfig + "," + pmConfig.DefaultMaxIoThreadsForAutoConfig);
                UnsafeNativeMethods.SetClrThreadPoolLimits(pmConfig.DefaultMaxWorkerThreadsForAutoConfig, pmConfig.DefaultMaxIoThreadsForAutoConfig, true);
            }

            // this is the code equivalent of setting maxconnection
            // Dev11 141729: Make autoConfig scale by default
            // Dev11 144842: PERF: Consider removing Max connection limit or changing the default value
            System.Net.ServicePointManager.DefaultConnectionLimit = Int32.MaxValue;

            // we call InitRequestQueue later, from FirstRequestInit, and set minFreeThreads and minLocalRequestFreeThreads
        }

        private void SetThreadPoolLimits()
        {
            try
            {
                ProcessModelSection pmConfig = RuntimeConfig.GetMachineConfig().ProcessModel;

                if (pmConfig.AutoConfig)
                {
                    // use recommendation in http://support.microsoft.com/?id=821268
                    SetAutoConfigLimits(pmConfig);
                }
                else if (pmConfig.MaxWorkerThreadsTimesCpuCount > 0 && pmConfig.MaxIoThreadsTimesCpuCount > 0)
                {
                    // check if the current limits are ok
                    int workerMax, ioMax;
                    ThreadPool.GetMaxThreads(out workerMax, out ioMax);

                    // only set if different
                    if (pmConfig.MaxWorkerThreadsTimesCpuCount != workerMax || pmConfig.MaxIoThreadsTimesCpuCount != ioMax)
                    {
                        Debug.Trace("ThreadPool", "SetThreadLimit: from " + workerMax + "," + ioMax + " to " + pmConfig.MaxWorkerThreadsTimesCpuCount + "," + pmConfig.MaxIoThreadsTimesCpuCount);
                        UnsafeNativeMethods.SetClrThreadPoolLimits(pmConfig.MaxWorkerThreadsTimesCpuCount, pmConfig.MaxIoThreadsTimesCpuCount, false);
                    }
                }

                if (pmConfig.MinWorkerThreadsTimesCpuCount > 0 || pmConfig.MinIoThreadsTimesCpuCount > 0)
                {
                    int currentMinWorkerThreads, currentMinIoThreads;
                    ThreadPool.GetMinThreads(out currentMinWorkerThreads, out currentMinIoThreads);

                    int newMinWorkerThreads = pmConfig.MinWorkerThreadsTimesCpuCount > 0 ? pmConfig.MinWorkerThreadsTimesCpuCount : currentMinWorkerThreads;
                    int newMinIoThreads = pmConfig.MinIoThreadsTimesCpuCount > 0 ? pmConfig.MinIoThreadsTimesCpuCount : currentMinIoThreads;

                    if (newMinWorkerThreads > 0 && newMinIoThreads > 0
                        && (newMinWorkerThreads != currentMinWorkerThreads || newMinIoThreads != currentMinIoThreads))
                        ThreadPool.SetMinThreads(newMinWorkerThreads, newMinIoThreads);
                }
            }
            catch
            {
            }
        }

        internal static void CheckApplicationEnabled()
        {
            // process App_Offline.htm file
            string appOfflineFile = Path.Combine(_theRuntime._appDomainAppPath, AppOfflineFileName);
            bool appOfflineFileFound = false;

            // monitor even if doesn't exist
            _theRuntime._fcm.StartMonitoringFile(appOfflineFile, new FileChangeEventHandler(_theRuntime.OnAppOfflineFileChange));

            // read the file into memory
            try
            {
                if (File.Exists(appOfflineFile))
                {
                    Debug.Trace("AppOffline", "File " + appOfflineFile + " exists. Using it.");

                    using (FileStream fs = new FileStream(appOfflineFile, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        if (fs.Length <= MaxAppOfflineFileLength)
                        {
                            int length = (int)fs.Length;

                            if (length > 0)
                            {
                                byte[] message = new byte[length];

                                if (fs.Read(message, 0, length) == length)
                                {
                                    // remember the message
                                    _theRuntime._appOfflineMessage = message;
                                    appOfflineFileFound = true;
                                }
                            }
                            else
                            {
                                // empty file
                                appOfflineFileFound = true;
                                _theRuntime._appOfflineMessage = new byte[0];
                            }
                        }
                    }
                }
            }
            catch
            {
                // ignore any IO errors reading the file
            }

            // throw if there is a valid App_Offline file
            if (appOfflineFileFound)
            {
                throw new HttpException(503, String.Empty);
            }

            // process the config setting
            HttpRuntimeSection runtimeConfig = RuntimeConfig.GetAppConfig().HttpRuntime;
            if (!runtimeConfig.Enable)
            {
                // throw 404 on first request init -- this will get cached until config changes
                throw new HttpException(404, String.Empty);
            }
        }

        [FileIOPermission(SecurityAction.Assert, Unrestricted = true)]
        private void CheckAccessToTempDirectory()
        {
            // The original check (in HostingInit) was done under process identity
            // this time we do it under hosting identity
            if (HostingEnvironment.HasHostingIdentity)
            {
                using (new ApplicationImpersonationContext())
                {
                    if (!System.Web.UI.Util.HasWriteAccessToDirectory(_tempDir))
                    {
                        throw new HttpException(SR.GetString(SR.No_codegen_access,
                            System.Web.UI.Util.GetCurrentAccountName(), _tempDir));
                    }
                }
            }
        }

        private void InitializeHealthMonitoring()
        {
#if !FEATURE_PAL // FEATURE_PAL does not enable IIS-based hosting features
            ProcessModelSection pmConfig = RuntimeConfig.GetMachineConfig().ProcessModel;
            int deadLockInterval = (int)pmConfig.ResponseDeadlockInterval.TotalSeconds;
            int requestQueueLimit = pmConfig.RequestQueueLimit;
            Debug.Trace("HealthMonitor", "Initalizing: ResponseDeadlockInterval=" + deadLockInterval);
            UnsafeNativeMethods.InitializeHealthMonitor(deadLockInterval, requestQueueLimit);
#endif // !FEATURE_PAL
        }

        private static void InitHttpConfiguration()
        {
            if (!_theRuntime._configInited)
            {
                _theRuntime._configInited = true;

                HttpConfigurationSystem.EnsureInit(null, true, true);

                // whenever possible report errors in the user's culture (from machine.config)
                // Note: this thread's culture is saved/restored during FirstRequestInit, so this is safe
                // see ASURT 81655

                GlobalizationSection globConfig = RuntimeConfig.GetAppLKGConfig().Globalization;
                if (globConfig != null)
                {
                    if (!String.IsNullOrEmpty(globConfig.Culture) &&
                        !StringUtil.StringStartsWithIgnoreCase(globConfig.Culture, "auto"))
                        SetCurrentThreadCultureWithAssert(HttpServerUtility.CreateReadOnlyCultureInfo(globConfig.Culture));

                    if (!String.IsNullOrEmpty(globConfig.UICulture) &&
                        !StringUtil.StringStartsWithIgnoreCase(globConfig.UICulture, "auto"))
                        Thread.CurrentThread.CurrentUICulture = HttpServerUtility.CreateReadOnlyCultureInfo(globConfig.UICulture);
                }

                // check for errors in <processModel> section
                RuntimeConfig appConfig = RuntimeConfig.GetAppConfig();
                object section = appConfig.ProcessModel;
                // check for errors in <hostingEnvironment> section
                section = appConfig.HostingEnvironment;
            }
        }

        private void InitHeaderEncoding()
        {
            HttpRuntimeSection runtimeConfig = RuntimeConfig.GetAppConfig().HttpRuntime;
            _enableHeaderChecking = runtimeConfig.EnableHeaderChecking;
        }



        internal static void PopulateIISVersionInformation()
        {
            if (IsEngineLoaded)
            {
                uint dwVersion;
                bool fIsIntegratedMode;
                UnsafeIISMethods.MgdGetIISVersionInformation(out dwVersion, out fIsIntegratedMode);

                if (dwVersion != 0)
                {
                    // High word is the major version; low word is the minor version (this is MAKELONG format)
                    _iisVersion = new Version((int)(dwVersion >> 16), (int)(dwVersion & 0xffff));
                    _useIntegratedPipeline = fIsIntegratedMode;
                }
            }
        }

        // Gets the version of IIS (7.0, 7.5, 8.0, etc.) that is hosting this application, or null if this application isn't IIS-hosted.
        // Should also return the correct version for IIS Express.
     

        // DevDivBugs 190952: public method for querying runtime pipeline mode
     

        internal static bool UseIntegratedPipeline
        {
            get
            {
                return _useIntegratedPipeline;
            }
        }


        /*
         * Process one step of the integrated pipeline
         *
         */

        internal static RequestNotificationStatus ProcessRequestNotification(IIS7WorkerRequest wr, HttpContext context)
        {
            return _theRuntime.ProcessRequestNotificationPrivate(wr, context);
        }

        private RequestNotificationStatus ProcessRequestNotificationPrivate(IIS7WorkerRequest wr, HttpContext context)
        {
            RequestNotificationStatus status = RequestNotificationStatus.Pending;
            try
            {
                int currentModuleIndex;
                bool isPostNotification;
                int currentNotification;

                // setup the HttpContext for this event/module combo
                UnsafeIISMethods.MgdGetCurrentNotificationInfo(wr.RequestContext, out currentModuleIndex, out isPostNotification, out currentNotification);

                context.CurrentModuleIndex = currentModuleIndex;
                context.IsPostNotification = isPostNotification;
                context.CurrentNotification = (RequestNotification)currentNotification;
#if DBG
                Debug.Trace("PipelineRuntime", "HttpRuntime::ProcessRequestNotificationPrivate: notification=" + context.CurrentNotification.ToString()
                            + ", isPost=" + context.IsPostNotification
                            + ", moduleIndex=" + context.CurrentModuleIndex);
#endif

                IHttpHandler handler = null;
                if (context.NeedToInitializeApp())
                {
#if DBG
                    Debug.Trace("FileChangesMonitorIgnoreSubdirChange",
                                "*** FirstNotification " + DateTime.Now.ToString("hh:mm:ss.fff", CultureInfo.InvariantCulture)
                                + ": _appDomainAppId=" + _appDomainAppId);
#endif
                    // First request initialization
                    try
                    {
                        EnsureFirstRequestInit(context);
                    }
                    catch
                    {
                        // If we are handling a DEBUG request, ignore the FirstRequestInit exception.
                        // This allows the HttpDebugHandler to execute, and lets the debugger attach to
                        // the process (VSWhidbey 358135)
                        if (!context.Request.IsDebuggingRequest)
                        {
                            throw;
                        }
                    }

                    context.Response.InitResponseWriter();
                    handler = HttpApplicationFactory.GetApplicationInstance(context);
                    if (handler == null)
                        throw new HttpException(SR.GetString(SR.Unable_create_app_object));

                    if (EtwTrace.IsTraceEnabled(EtwTraceLevel.Verbose, EtwTraceFlags.Infrastructure)) EtwTrace.Trace(EtwTraceType.ETW_TYPE_START_HANDLER, context.WorkerRequest, handler.GetType().FullName, "Start");

                    HttpApplication app = handler as HttpApplication;
                    if (app != null)
                    {
                        // associate the context with an application instance
                        app.AssignContext(context);
                    }
                }

                // this may throw, and should be called after app initialization
                wr.SynchronizeVariables(context);

                if (context.ApplicationInstance != null)
                {
                    // process request
                    IAsyncResult ar = context.ApplicationInstance.BeginProcessRequestNotification(context, _requestNotificationCompletionCallback);

                    if (ar.CompletedSynchronously)
                    {
                        status = RequestNotificationStatus.Continue;
                    }
                }
                else if (handler != null)
                {
                    // HttpDebugHandler is processed here
                    handler.ProcessRequest(context);
                    status = RequestNotificationStatus.FinishRequest;
                }
                else
                {
                    status = RequestNotificationStatus.Continue;
                }
            }
            catch (Exception e)
            {
                status = RequestNotificationStatus.FinishRequest;
                context.Response.InitResponseWriter();
                // errors are handled in HttpRuntime::FinishRequestNotification
                context.AddError(e);
            }

            if (status != RequestNotificationStatus.Pending)
            {
                // we completed synchronously
                FinishRequestNotification(wr, context, ref status);
            }

#if DBG
            Debug.Trace("PipelineRuntime", "HttpRuntime::ProcessRequestNotificationPrivate: status=" + status.ToString());
#endif

            return status;
        }

        private void FinishRequestNotification(IIS7WorkerRequest wr, HttpContext context, ref RequestNotificationStatus status)
        {

            Debug.Assert(status != RequestNotificationStatus.Pending, "status != RequestNotificationStatus.Pending");

            HttpApplication app = context.ApplicationInstance;

            if (context.NotificationContext.RequestCompleted)
            {
                status = RequestNotificationStatus.FinishRequest;
            }

            // check if the app offline or whether an error has occurred, and report the condition
            context.ReportRuntimeErrorIfExists(ref status);

            // we do not return FinishRequest for LogRequest or EndRequest
            if (status == RequestNotificationStatus.FinishRequest
                && (context.CurrentNotification == RequestNotification.LogRequest
                    || context.CurrentNotification == RequestNotification.EndRequest))
            {
                status = RequestNotificationStatus.Continue;
            }

            IntPtr requestContext = wr.RequestContext;
            bool sendHeaders = UnsafeIISMethods.MgdIsLastNotification(requestContext, status);
            try
            {
                context.Response.UpdateNativeResponse(sendHeaders);
            }
            catch (Exception e)
            {
                // if we catch an exception here then
                // i) clear cached response body bytes on the worker request
                // ii) clear the managed headers, the IIS native headers, the mangaged httpwriter response buffers, and the native IIS response buffers
                // iii) attempt to format the exception and write it to the response
                wr.UnlockCachedResponseBytes();
                context.AddError(e);
                context.ReportRuntimeErrorIfExists(ref status);
                try
                {
                    context.Response.UpdateNativeResponse(sendHeaders);
                }
                catch
                {
                }
            }

            if (sendHeaders)
            {
                context.FinishPipelineRequest();
            }

            // Perf optimization: dispose managed context if possible (no need to try if status is pending)
            if (status != RequestNotificationStatus.Pending)
            {
                PipelineRuntime.DisposeHandler(context, requestContext, status);
            }
        }

        internal static void FinishPipelineRequest(HttpContext context)
        {
            // Remember that first request is done
            _theRuntime._firstRequestCompleted = true;

            // need to raise OnRequestCompleted while within the ThreadContext so that things like User, CurrentCulture, etc. are available
            context.RaiseOnRequestCompleted();

            context.Request.Dispose();
            context.Response.Dispose();
            HttpApplication app = context.ApplicationInstance;
            if (null != app)
            {
                ThreadContext threadContext = context.IndicateCompletionContext;
                if (threadContext != null)
                {
                    if (!threadContext.HasBeenDisassociatedFromThread)
                    {
                        lock (threadContext)
                        {
                            if (!threadContext.HasBeenDisassociatedFromThread)
                            {
                                threadContext.DisassociateFromCurrentThread();
                                context.IndicateCompletionContext = null;
                                context.InIndicateCompletion = false;
                            }
                        }
                    }
                }
                app.ReleaseAppInstance();
            }

            SetExecutionTimePerformanceCounter(context);
            UpdatePerfCounters(context.Response.StatusCode);
            if (EtwTrace.IsTraceEnabled(EtwTraceLevel.Verbose, EtwTraceFlags.Infrastructure)) EtwTrace.Trace(EtwTraceType.ETW_TYPE_END_HANDLER, context.WorkerRequest);

            // In case of a HostingInit() error, app domain should not stick around
            if (HostingInitFailed)
            {
                Debug.Trace("AppDomainFactory", "Shutting down appdomain because of HostingInit error");
                ShutdownAppDomain(ApplicationShutdownReason.HostingEnvironment, "HostingInit error");
            }
        }


        /*
         * Process one request
         */
        private void ProcessRequestInternal(HttpWorkerRequest wr)
        {
            // Count active requests
            Interlocked.Increment(ref _activeRequestCount);

            if (_disposingHttpRuntime)
            {
                // Dev11 333176: An appdomain is unloaded before all requests are served, resulting in System.AppDomainUnloadedException during isapi completion callback
                //
                // HttpRuntim.Dispose could have already finished on a different thread when we had no active requests
                // In this case we are about to start or already started unloading the appdomain so we will reject the request the safest way possible
                try
                {
                    wr.SendStatus(503, "Server Too Busy");
                    wr.SendKnownResponseHeader(HttpWorkerRequest.HeaderContentType, "text/html; charset=utf-8");
                    byte[] body = Encoding.ASCII.GetBytes("<html><body>Server Too Busy</body></html>");
                    wr.SendResponseFromMemory(body, body.Length);
                    // this will flush synchronously because of HttpRuntime.ShutdownInProgress
                    wr.FlushResponse(true);
                    wr.EndOfRequest();
                }
                finally
                {
                    Interlocked.Decrement(ref _activeRequestCount);
                }
                return;
            }

            // Construct the Context on HttpWorkerRequest, hook everything together
            HttpContext context;

            try
            {
                context = new HttpContext(wr, false /* initResponseWriter */);
            }
            catch
            {
                try
                {
                    // If we fail to create the context for any reason, send back a 400 to make sure
                    // the request is correctly closed (relates to VSUQFE3962)
                    wr.SendStatus(400, "Bad Request");
                    wr.SendKnownResponseHeader(HttpWorkerRequest.HeaderContentType, "text/html; charset=utf-8");
                    byte[] body = Encoding.ASCII.GetBytes("<html><body>Bad Request</body></html>");
                    wr.SendResponseFromMemory(body, body.Length);
                    wr.FlushResponse(true);
                    wr.EndOfRequest();
                    return;
                }
                finally
                {
                    Interlocked.Decrement(ref _activeRequestCount);
                }
            }

            wr.SetEndOfSendNotification(_asyncEndOfSendCallback, context);

            HostingEnvironment.IncrementBusyCount();

            try
            {
                // First request initialization
                try
                {
                    EnsureFirstRequestInit(context);
                }
                catch
                {
                    // If we are handling a DEBUG request, ignore the FirstRequestInit exception.
                    // This allows the HttpDebugHandler to execute, and lets the debugger attach to
                    // the process (VSWhidbey 358135)
                    if (!context.Request.IsDebuggingRequest)
                    {
                        throw;
                    }
                }

                // Init response writer (after we have config in first request init)
                // no need for impersonation as it is handled in config system
                context.Response.InitResponseWriter();

                // Get application instance
                IHttpHandler app = HttpApplicationFactory.GetApplicationInstance(context);

                if (app == null)
                    throw new HttpException(SR.GetString(SR.Unable_create_app_object));

                if (EtwTrace.IsTraceEnabled(EtwTraceLevel.Verbose, EtwTraceFlags.Infrastructure)) EtwTrace.Trace(EtwTraceType.ETW_TYPE_START_HANDLER, context.WorkerRequest, app.GetType().FullName, "Start");

                if (app is IHttpAsyncHandler)
                {
                    // asynchronous handler
                    IHttpAsyncHandler asyncHandler = (IHttpAsyncHandler)app;
                    context.AsyncAppHandler = asyncHandler;
                    asyncHandler.BeginProcessRequest(context, _handlerCompletionCallback, context);
                }
                else
                {
                    // synchronous handler
                    app.ProcessRequest(context);
                    FinishRequest(context.WorkerRequest, context, null);
                }
            }
            catch (Exception e)
            {
                context.Response.InitResponseWriter();
                FinishRequest(wr, context, e);
            }
        }

        private void RejectRequestInternal(HttpWorkerRequest wr, bool silent)
        {
            // Construct the Context on HttpWorkerRequest, hook everything together
            HttpContext context = new HttpContext(wr, false /* initResponseWriter */);
            wr.SetEndOfSendNotification(_asyncEndOfSendCallback, context);

            // Count active requests
            Interlocked.Increment(ref _activeRequestCount);
            HostingEnvironment.IncrementBusyCount();

            if (silent)
            {
                context.Response.InitResponseWriter();
                FinishRequest(wr, context, null);
            }
            else
            {
                PerfCounters.IncrementGlobalCounter(GlobalPerfCounter.REQUESTS_REJECTED);
                PerfCounters.IncrementCounter(AppPerfCounter.APP_REQUESTS_REJECTED);
                try
                {
                    throw new HttpException(503, SR.GetString(SR.Server_too_busy));
                }
                catch (Exception e)
                {
                    context.Response.InitResponseWriter();
                    FinishRequest(wr, context, e);
                }
            }
        }

        internal static void ReportAppOfflineErrorMessage(HttpResponse response, byte[] appOfflineMessage)
        {
            response.StatusCode = 503;
            response.ContentType = "text/html";
            response.AddHeader("Retry-After", "3600");
            response.OutputStream.Write(appOfflineMessage, 0, appOfflineMessage.Length);
        }

        /*
         * Finish processing request, sync or async
         */
        private void FinishRequest(HttpWorkerRequest wr, HttpContext context, Exception e)
        {
            HttpResponse response = context.Response;

            if (EtwTrace.IsTraceEnabled(EtwTraceLevel.Verbose, EtwTraceFlags.Infrastructure)) EtwTrace.Trace(EtwTraceType.ETW_TYPE_END_HANDLER, context.WorkerRequest);

            SetExecutionTimePerformanceCounter(context);

            // Flush in case of no error
            if (e == null)
            {
                // impersonate around PreSendHeaders / PreSendContent
                using (new ClientImpersonationContext(context, false))
                {
                    try
                    {
                        // this sends the actual content in most cases
                        response.FinalFlushAtTheEndOfRequestProcessing();
                    }
                    catch (Exception eFlush)
                    {
                        e = eFlush;
                    }
                }
            }

            // Report error if any
            if (e != null)
            {
                using (new DisposableHttpContextWrapper(context))
                {

                    // if the custom encoder throws, it might interfere with returning error information
                    // to the client, so we force use of the default encoder
                    context.DisableCustomHttpEncoder = true;

                    if (_appOfflineMessage != null)
                    {
                        try
                        {
                            ReportAppOfflineErrorMessage(response, _appOfflineMessage);
                            response.FinalFlushAtTheEndOfRequestProcessing();
                        }
                        catch
                        {
                        }
                    }
                    else
                    {
                        // when application is on UNC share the code below must
                        // be run while impersonating the token given by IIS
                        using (new ApplicationImpersonationContext())
                        {
                            try
                            {
                                try
                                {
                                    // try to report error in a way that could possibly throw (a config exception)
                                    response.ReportRuntimeError(e, true /*canThrow*/, false);
                                }
                                catch (Exception eReport)
                                {
                                    // report the config error in a way that would not throw
                                    response.ReportRuntimeError(eReport, false /*canThrow*/, false);
                                }

                                response.FinalFlushAtTheEndOfRequestProcessing();
                            }
                            catch
                            {
                            }
                        }
                    }
                }
            }

            // Remember that first request is done
            _firstRequestCompleted = true;


            // In case we reporting HostingInit() error, app domain should not stick around
            if (_hostingInitFailed)
            {
                Debug.Trace("AppDomainFactory", "Shutting down appdomain because of HostingInit error");
                ShutdownAppDomain(ApplicationShutdownReason.HostingEnvironment, "HostingInit error");
            }

            // Check status code and increment proper counter
            // If it's an error status code (i.e. 400 or higher), increment the proper perf counters
            int statusCode = response.StatusCode;
            UpdatePerfCounters(statusCode);

            context.FinishRequestForCachedPathData(statusCode);

            // ---- exceptions from EndOfRequest as they will prevent proper request cleanup
            // Since the exceptions are not expected here we want to log them
            try
            {
                wr.EndOfRequest();
            }
            catch (Exception ex)
            {
                WebBaseEvent.RaiseRuntimeError(ex, this);
            }

            // Count active requests
            HostingEnvironment.DecrementBusyCount();
            Interlocked.Decrement(ref _activeRequestCount);

            // Schedule more work if some requests are queued
            if (_requestQueue != null)
                _requestQueue.ScheduleMoreWorkIfNeeded();
        }

        //
        // Make sure shutdown happens only once
        //

        private bool InitiateShutdownOnce()
        {
            if (_shutdownInProgress)
                return false;

            lock (this)
            {
                if (_shutdownInProgress)
                    return false;
                _shutdownInProgress = true;
            }

            return true;
        }


        private void ReleaseResourcesAndUnloadAppDomain(Object state /*not used*/)
        {
#if DBG
            Debug.Trace("FileChangesMonitorIgnoreSubdirChange",
                        "*** ReleaseResourcesAndUnloadAppDomain " + DateTime.Now.ToString("hh:mm:ss.fff", CultureInfo.InvariantCulture)
                        + ": _appDomainAppId=" + _appDomainAppId);
#endif
            Debug.Trace("AppDomainFactory", "ReleaseResourcesAndUnloadAppDomain, Id=" + _appDomainAppId
                        + " DomainId = " + _appDomainId
                        + " Stack = " + Environment.StackTrace);

            try
            {
                PerfCounters.IncrementGlobalCounter(GlobalPerfCounter.APPLICATION_RESTARTS);
            }
            catch
            {
            }

            // Release all resources
            try
            {
                Dispose();
            }
            catch
            {
            }

            Thread.Sleep(250);

            AddAppDomainTraceMessage("before Unload");

            for (; ; )
            {
                try
                {
                    AppDomain.Unload(Thread.GetDomain());
                }
                catch (CannotUnloadAppDomainException)
                {
                    Debug.Assert(false);
                }
                catch (Exception e)
                {
                    Debug.Trace("AppDomainFactory", "AppDomain.Unload exception: " + e + "; Id=" + _appDomainAppId);
                    if (!BuildManagerHost.InClientBuildManager)
                    {
                        // Avoid calling Exception.ToString if we are in the ClientBuildManager (Dev10 bug 824659)
                        AddAppDomainTraceMessage("Unload Exception: " + e);
                    }
                    throw;
                }
            }
        }

        private static void SetExecutionTimePerformanceCounter(HttpContext context)
        {
            // Set the Request Execution time perf counter
            TimeSpan elapsed = DateTime.UtcNow.Subtract(context.WorkerRequest.GetStartTime());
            long milli = elapsed.Ticks / TimeSpan.TicksPerMillisecond;

            if (milli > Int32.MaxValue)
                milli = Int32.MaxValue;

            PerfCounters.SetGlobalCounter(GlobalPerfCounter.REQUEST_EXECUTION_TIME, (int)milli);
            PerfCounters.SetCounter(AppPerfCounter.APP_REQUEST_EXEC_TIME, (int)milli);
        }

        private static void UpdatePerfCounters(int statusCode)
        {
            if (400 <= statusCode)
            {
                PerfCounters.IncrementCounter(AppPerfCounter.REQUESTS_FAILED);
                switch (statusCode)
                {
                    case 401: // Not authorized
                        PerfCounters.IncrementCounter(AppPerfCounter.REQUESTS_NOT_AUTHORIZED);
                        break;
                    case 404: // Not found
                    case 414: // Not found
                        PerfCounters.IncrementCounter(AppPerfCounter.REQUESTS_NOT_FOUND);
                        break;
                }
            }
            else
            {
                // If status code is not in the 400-599 range (i.e. 200-299 success or 300-399 redirection),
                // count it as a successful request.
                PerfCounters.IncrementCounter(AppPerfCounter.REQUESTS_SUCCEDED);
            }
        }

        private void WaitForRequestsToFinish(int waitTimeoutMs)
        {
            DateTime waitLimit = DateTime.UtcNow.AddMilliseconds(waitTimeoutMs);

            for (; ; )
            {
                if (_activeRequestCount == 0 && (_requestQueue == null || _requestQueue.IsEmpty))
                    break;

                Thread.Sleep(250);

                // only apply timeout if a managed debugger is not attached
                if (!System.Diagnostics.Debugger.IsAttached && DateTime.UtcNow > waitLimit)
                {
                    break; // give it up
                }
            }
        }

        /*
         * Cleanup of all unmananged state
         */
        private void Dispose()
        {
            // get shutdown timeout from config
            int drainTimeoutSec = HttpRuntimeSection.DefaultShutdownTimeout;
            try
            {
                HttpRuntimeSection runtimeConfig = RuntimeConfig.GetAppLKGConfig().HttpRuntime;
                if (runtimeConfig != null)
                {
                    drainTimeoutSec = (int)runtimeConfig.ShutdownTimeout.TotalSeconds;
                }

                // before aborting compilation give time to drain (new requests are no longer coming at this point)
                WaitForRequestsToFinish(drainTimeoutSec * 1000);

                // reject remaining queued requests
                if (_requestQueue != null)
                    _requestQueue.Drain();
            }
            finally
            {
                // By this time all new requests should be directed to a newly created app domain
                // But there might be requests that got dispatched to this old app domain but have not reached ProcessRequestInternal yet
                // Signal ProcessRequestInternal to reject them immediately without initiating async operations
                _disposingHttpRuntime = true;
            }

            // give it a little more time to drain
            WaitForRequestsToFinish((drainTimeoutSec * 1000) / 6);


            // wait for pending async io to complete,  prior to aborting requests
            // this isn't necessary for IIS 7, where the async sends are always done
            // from native code with native buffers
            System.Web.Hosting.ISAPIWorkerRequestInProcForIIS6.WaitForPendingAsyncIo();

            // For IIS7 integrated pipeline, wait until GL_APPLICATION_STOP fires and
            // there are no active calls to IndicateCompletion before unloading the AppDomain
            if (HttpRuntime.UseIntegratedPipeline)
            {
                PipelineRuntime.WaitForRequestsToDrain();
            }
            else
            {
                // wait for all active requests to complete
                while (_activeRequestCount != 0)
                {
                    Thread.Sleep(250);
                }
            }


            // Dispose AppDomainShutdownTimer
            DisposeAppDomainShutdownTimer();

            // kill all remaining requests (and the timeout timer)
            _timeoutManager.Stop();
            AppDomainResourcePerfCounters.Stop();

#if !FEATURE_PAL // FEATURE_PAL does not enable IIS-based hosting features
            // double check for pending async io
            System.Web.Hosting.ISAPIWorkerRequestInProcForIIS6.WaitForPendingAsyncIo();

            // stop sqlcachedependency polling
            SqlCacheDependencyManager.Dispose((drainTimeoutSec * 1000) / 2);
#endif // !FEATURE_PAL
            // cleanup cache (this ends all sessions)
            HealthMonitoringManager.IsCacheDisposed = true; // HMM is the only place internally where we care if the Cache is disposed or not.
            if (_cachePublic != null)
            {
                var oCache = HttpRuntime.Cache.GetObjectCache(createIfDoesNotExist: false);
                var iCache = HttpRuntime.Cache.GetInternalCache(createIfDoesNotExist: false);
                if (oCache != null)
                {
                    oCache.Dispose();
                }
                if (iCache != null)
                {
                    iCache.Dispose();
                }
            }

            // app on end, cleanup app instances
            HttpApplicationFactory.EndApplication();  // call app_onEnd

            // stop file changes monitor
            _fcm.Stop();

            // stop health monitoring timer
            HealthMonitoringManager.Shutdown();
        }

        /*
         * Async completion of IIS7 pipeline (unlike OnHandlerCompletion, this may fire more than once).
         */
        private void OnRequestNotificationCompletion(IAsyncResult ar)
        {
            try
            {
                OnRequestNotificationCompletionHelper(ar);
            }
            catch (Exception e)
            {
                ApplicationManager.RecordFatalException(e);
                throw;
            }
        }

        private void OnRequestNotificationCompletionHelper(IAsyncResult ar)
        {
            if (ar.CompletedSynchronously)
            {
                Debug.Trace("PipelineRuntime", "OnRequestNotificationCompletion: completed synchronously");
                return;
            }

            Debug.Trace("PipelineRuntime", "OnRequestNotificationCompletion: completed asynchronously");

            RequestNotificationStatus status = RequestNotificationStatus.Continue;
            HttpContext context = (HttpContext)ar.AsyncState;
            IIS7WorkerRequest wr = context.WorkerRequest as IIS7WorkerRequest;

            try
            {
                context.ApplicationInstance.EndProcessRequestNotification(ar);
            }
            catch (Exception e)
            {
                status = RequestNotificationStatus.FinishRequest;
                context.AddError(e);
            }

            // RequestContext is set to null if this is the last notification, so we need to save it
            // for the call to PostCompletion
            IntPtr requestContext = wr.RequestContext;

            FinishRequestNotification(wr, context, ref status);

            // set the notification context to null since we are exiting this notification
            context.NotificationContext = null;

            // Indicate completion to IIS, so that it can resume
            // request processing on an IIS thread
            Debug.Trace("PipelineRuntime", "OnRequestNotificationCompletion(" + status + ")");
            int result = UnsafeIISMethods.MgdPostCompletion(requestContext, status);
            Misc.ThrowIfFailedHr(result);
        }

        /*
         * Async completion of managed pipeline (called at most one time).
         */
        private void OnHandlerCompletion(IAsyncResult ar)
        {
            HttpContext context = (HttpContext)ar.AsyncState;

            try
            {
                context.AsyncAppHandler.EndProcessRequest(ar);
            }
            catch (Exception e)
            {
                context.AddError(e);
            }
            finally
            {
                // no longer keep AsyncAppHandler poiting to the application
                // is only needed to call EndProcessRequest
                context.AsyncAppHandler = null;
            }

            FinishRequest(context.WorkerRequest, context, context.Error);
        }

        /*
         * Notification from worker request that it is done writing from buffer
         * so that the buffers can be recycled
         */
        private void EndOfSendCallback(HttpWorkerRequest wr, Object arg)
        {
            Debug.Trace("PipelineRuntime", "HttpRuntime.EndOfSendCallback");
            HttpContext context = (HttpContext)arg;
            context.Request.Dispose();
            context.Response.Dispose();
        }

        /*
         * Notification when something in the bin directory changed
         */
        private void OnCriticalDirectoryChange(Object sender, FileChangeEvent e)
        {
            // shutdown the app domain
            Debug.Trace("AppDomainFactory", "Shutting down appdomain because of bin dir change or directory rename." +
                " FileName=" + e.FileName + " Action=" + e.Action);

            ApplicationShutdownReason reason = ApplicationShutdownReason.None;
            string directoryName = new DirectoryInfo(e.FileName).Name;

            string message = FileChangesMonitor.GenerateErrorMessage(e.Action);
            message = (message != null) ? message + directoryName : directoryName + " dir change or directory rename";

            if (StringUtil.EqualsIgnoreCase(directoryName, CodeDirectoryName))
            {
                reason = ApplicationShutdownReason.CodeDirChangeOrDirectoryRename;
            }
            else if (StringUtil.EqualsIgnoreCase(directoryName, ResourcesDirectoryName))
            {
                reason = ApplicationShutdownReason.ResourcesDirChangeOrDirectoryRename;
            }
            else if (StringUtil.EqualsIgnoreCase(directoryName, BrowsersDirectoryName))
            {
                reason = ApplicationShutdownReason.BrowsersDirChangeOrDirectoryRename;
            }
            else if (StringUtil.EqualsIgnoreCase(directoryName, BinDirectoryName))
            {
                reason = ApplicationShutdownReason.BinDirChangeOrDirectoryRename;
            }

            if (e.Action == FileAction.Added)
            {
                // Make sure HttpRuntime does not ignore the appdomain shutdown if a file is added (VSWhidbey 363481)
                HttpRuntime.SetUserForcedShutdown();

                Debug.Trace("AppDomainFactorySpecial", "Call SetUserForcedShutdown: FileName=" + e.FileName + "; now=" + DateTime.Now);
            }

            ShutdownAppDomain(reason, message);
        }

        /**
         * Coalesce file change notifications to minimize sharing violations and AppDomain restarts (ASURT 147492)
         */
        internal static void CoalesceNotifications()
        {
            int waitChangeNotification = HttpRuntimeSection.DefaultWaitChangeNotification;
            int maxWaitChangeNotification = HttpRuntimeSection.DefaultMaxWaitChangeNotification;
            try
            {
                HttpRuntimeSection config = RuntimeConfig.GetAppLKGConfig().HttpRuntime;
                if (config != null)
                {
                    waitChangeNotification = config.WaitChangeNotification;
                    maxWaitChangeNotification = config.MaxWaitChangeNotification;
                }
            }
            catch
            {
            }

            if (waitChangeNotification == 0 || maxWaitChangeNotification == 0)
                return;

            DateTime maxWait = DateTime.UtcNow.AddSeconds(maxWaitChangeNotification);
            // Coalesce file change notifications
            try
            {
                while (DateTime.UtcNow < maxWait)
                {
                    if (DateTime.UtcNow > _theRuntime.LastShutdownAttemptTime.AddSeconds(waitChangeNotification))
                        break;

                    Thread.Sleep(250);
                }
            }
            catch
            {
            }
        }

        // appdomain shutdown eventhandler
        internal static event BuildManagerHostUnloadEventHandler AppDomainShutdown;

        internal static void OnAppDomainShutdown(BuildManagerHostUnloadEventArgs e)
        {
            if (AppDomainShutdown != null)
            {
                AppDomainShutdown(_theRuntime, e);
            }
        }

        internal static void SetUserForcedShutdown()
        {
            _theRuntime._userForcedShutdown = true;
        }

        /*
         * Shutdown the current app domain
         */
        internal static bool ShutdownAppDomain(ApplicationShutdownReason reason, string message)
        {
            return ShutdownAppDomainWithStackTrace(reason, message, null /*stackTrace*/);
        }

        /*
         * Shutdown the current app domain with a stack trace.  This is useful for callers that are running
         * on a QUWI callback, and wouldn't provide a meaningful stack trace by default.
         */
        internal static bool ShutdownAppDomainWithStackTrace(ApplicationShutdownReason reason, string message, string stackTrace)
        {
            SetShutdownReason(reason, message);
            return ShutdownAppDomain(stackTrace);
        }

        private static bool ShutdownAppDomain(string stackTrace)
        {
#if DBG
            Debug.Trace("FileChangesMonitorIgnoreSubdirChange",
                        "*** ShutdownAppDomain " + DateTime.Now.ToString("hh:mm:ss.fff", CultureInfo.InvariantCulture)
                        + ": _appDomainAppId=" + HttpRuntime.AppDomainAppId);
#endif
            // Ignore notifications during the processing of the first request (ASURT 100335)
            // skip this if LastShutdownAttemptTime has been set
            if (_theRuntime.LastShutdownAttemptTime == DateTime.MinValue && !_theRuntime._firstRequestCompleted && !_theRuntime._userForcedShutdown)
            {
                // check the timeout (don't disable notifications forever
                int delayTimeoutSec = HttpRuntimeSection.DefaultDelayNotificationTimeout;

                try
                {
                    RuntimeConfig runtimeConfig = RuntimeConfig.GetAppLKGConfig();
                    if (runtimeConfig != null)
                    {
                        HttpRuntimeSection runtimeSection = runtimeConfig.HttpRuntime;
                        if (runtimeSection != null)
                        {
                            delayTimeoutSec = (int)runtimeSection.DelayNotificationTimeout.TotalSeconds;

                            if (DateTime.UtcNow < _theRuntime._firstRequestStartTime.AddSeconds(delayTimeoutSec))
                            {
                                Debug.Trace("AppDomainFactory", "ShutdownAppDomain IGNORED (1st request is not done yet), Id = " + AppDomainAppId);
                                return false;
                            }
                        }
                    }
                }
                catch
                {
                }
            }

            try
            {
                _theRuntime.RaiseShutdownWebEventOnce();
            }
            catch
            {
                // VSWhidbey 444472: if an exception is thrown, we consume it and continue executing the following code.
            }

            // Update last time ShutdownAppDomain was called
            _theRuntime.LastShutdownAttemptTime = DateTime.UtcNow;

            if (!HostingEnvironment.ShutdownInitiated)
            {
                // This shutdown is not triggered by hosting environment - let it do the job
                HostingEnvironment.InitiateShutdownWithoutDemand();
                return true;
            }

            //WOS 1400290: CantUnloadAppDomainException in ISAPI mode, wait until HostingEnvironment.ShutdownThisAppDomainOnce completes
            if (HostingEnvironment.ShutdownInProgress)
            {
                return false;
            }

            // Make sure we don't go through shutdown logic many times
            if (!_theRuntime.InitiateShutdownOnce())
                return false;

            Debug.Trace("AppDomainFactory", "ShutdownAppDomain, Id = " + AppDomainAppId + ", ShutdownInProgress=" + ShutdownInProgress
                        + ", ShutdownMessage=" + _theRuntime._shutDownMessage);

            if (String.IsNullOrEmpty(stackTrace) && !BuildManagerHost.InClientBuildManager)
            {
                // Avoid calling Environment.StackTrace if we are in the ClientBuildManager (Dev10 bug 824659)

                // Instrument to be able to see what's causing a shutdown
                new EnvironmentPermission(PermissionState.Unrestricted).Assert();
                try
                {
                    _theRuntime._shutDownStack = Environment.StackTrace;
                }
                finally
                {
                    CodeAccessPermission.RevertAssert();
                }
            }
            else
            {
                _theRuntime._shutDownStack = stackTrace;
            }

            // Notify when appdomain is about to shutdown.
            OnAppDomainShutdown(new BuildManagerHostUnloadEventArgs(_theRuntime._shutdownReason));

            // unload app domain from another CLR thread
            ThreadPool.QueueUserWorkItem(_theRuntime._appDomainUnloadallback);

            return true;
        }

     

        /*
         * Notification when app-level Config changed
         */
     

        // Intrumentation to remember the overwhelming file change
        internal static void SetShutdownReason(ApplicationShutdownReason reason, String message)
        {
            if (_theRuntime._shutdownReason == ApplicationShutdownReason.None)
            {
                _theRuntime._shutdownReason = reason;
            }

            SetShutdownMessage(message);
        }

        internal static void SetShutdownMessage(String message)
        {
            if (message != null)
            {
                if (_theRuntime._shutDownMessage == null)
                    _theRuntime._shutDownMessage = message;
                else
                    _theRuntime._shutDownMessage += "\r\n" + message;
            }
        }


        // public method is on HostingEnvironment
        internal static ApplicationShutdownReason ShutdownReason
        {
            get { return _theRuntime._shutdownReason; }
        }

        //
        // public static APIs
        //

        /*
         * Process one request
         */

    


        internal static void ProcessRequestNoDemand(HttpWorkerRequest wr)
        {
            RequestQueue rq = _theRuntime._requestQueue;

            wr.UpdateInitialCounters();

            if (rq != null)  // could be null before first request
                wr = rq.GetRequestToExecute(wr);

            if (wr != null)
            {
                CalculateWaitTimeAndUpdatePerfCounter(wr);
                wr.ResetStartTime();
                ProcessRequestNow(wr);
            }
        }


        private static void CalculateWaitTimeAndUpdatePerfCounter(HttpWorkerRequest wr)
        {
            DateTime begin = wr.GetStartTime();

            TimeSpan elapsed = DateTime.UtcNow.Subtract(begin);
            long milli = elapsed.Ticks / TimeSpan.TicksPerMillisecond;

            if (milli > Int32.MaxValue)
                milli = Int32.MaxValue;

            PerfCounters.SetGlobalCounter(GlobalPerfCounter.REQUEST_WAIT_TIME, (int)milli);
            PerfCounters.SetCounter(AppPerfCounter.APP_REQUEST_WAIT_TIME, (int)milli);
        }

        internal static void ProcessRequestNow(HttpWorkerRequest wr)
        {
            _theRuntime.ProcessRequestInternal(wr);
        }

      






        private DateTime LastShutdownAttemptTime
        {
            get
            {
                DateTime dt;
                lock (this)
                {
                    dt = _lastShutdownAttemptTime;
                }
                return dt;
            }
            set
            {
                lock (this)
                {
                    _lastShutdownAttemptTime = value;
                }
            }
        }

        internal static Profiler Profile
        {
            get
            {
                return _theRuntime._profiler;
            }
        }

        internal static bool IsTrustLevelInitialized
        {
            get
            {
                return !HostingEnvironment.IsHosted || TrustLevel != null;
            }
        }

        internal static NamedPermissionSet NamedPermissionSet
        {
            get
            {
                // Make sure we have already initialized the trust level
                // 


                return _theRuntime._namedPermissionSet;
            }
        }

        internal static PolicyLevel PolicyLevel
        {
            get
            {
                return _theRuntime._policyLevel;
            }
        }



        /*
         * Check that the current trust level allows access to a path.  Throw if it doesn't,
         */
        internal static void CheckFilePermission(string path)
        {
            CheckFilePermission(path, false);
        }

        internal static void CheckFilePermission(string path, bool writePermissions)
        {
            if (!HasFilePermission(path, writePermissions))
            {
                throw new HttpException(SR.GetString(SR.Access_denied_to_path, GetSafePath(path)));
            }
        }


        internal static bool HasFilePermission(string path, bool writePermissions)
        {
            // WOS #1523618: need to skip this check for HttpResponse.ReportRuntimeError when reporting an
            // InitializationException (e.g., necessary to display line info for ConfigurationException).

            if (TrustLevel == null && InitializationException != null)
            {
                return true;
            }

            // Make sure we have already initialized the trust level
            Debug.Assert(TrustLevel != null || !HostingEnvironment.IsHosted, "TrustLevel != null || !HostingEnvironment.IsHosted");

            // If we don't have a NamedPermissionSet, we're in full trust
            if (NamedPermissionSet == null)
                return true;

            bool fAccess = false;

            // Check that the user has permission to the path
            IPermission allowedPermission = NamedPermissionSet.GetPermission(typeof(FileIOPermission));
            if (allowedPermission != null)
            {
                IPermission askedPermission = null;
                try
                {
                    if (!writePermissions)
                        askedPermission = new FileIOPermission(FileIOPermissionAccess.Read, path);
                    else
                        askedPermission = new FileIOPermission(FileIOPermissionAccess.AllAccess, path);
                }
                catch
                {
                    // This could happen if the path is not absolute
                    return false;
                }
                fAccess = askedPermission.IsSubsetOf(allowedPermission);
            }

            return fAccess;
        }


        internal static bool HasPathDiscoveryPermission(string path)
        {
            // WOS #1523618: need to skip this check for HttpResponse.ReportRuntimeError when reporting an
            // InitializationException (e.g., necessary to display line info for ConfigurationException).

            if (TrustLevel == null && InitializationException != null)
            {
                return true;
            }

            // Make sure we have already initialized the trust level
            Debug.Assert(TrustLevel != null || !HostingEnvironment.IsHosted);

            // If we don't have a NamedPermissionSet, we're in full trust
            if (NamedPermissionSet == null)
                return true;

            bool fAccess = false;

            // Check that the user has permission to the path
            IPermission allowedPermission = NamedPermissionSet.GetPermission(typeof(FileIOPermission));
            if (allowedPermission != null)
            {
                IPermission askedPermission = new FileIOPermission(FileIOPermissionAccess.PathDiscovery, path);
                fAccess = askedPermission.IsSubsetOf(allowedPermission);
            }

            return fAccess;

        }


        internal static string GetSafePath(string path)
        {
            if (String.IsNullOrEmpty(path))
                return path;

            try
            {
                if (HasPathDiscoveryPermission(path)) // could throw on bad filenames
                    return path;
            }
            catch
            {
            }

            return Path.GetFileName(path);
        }

        /*
         * Check that the current trust level allows Unmanaged access
         */
  

        internal static bool HasAspNetHostingPermission(AspNetHostingPermissionLevel level)
        {

            // Make sure we have already initialized the trust level
            // 



            // If we don't have a NamedPermissionSet, we're in full trust
            if (NamedPermissionSet == null)
                return true;

            AspNetHostingPermission permission = (AspNetHostingPermission)NamedPermissionSet.GetPermission(
                typeof(AspNetHostingPermission));
            if (permission == null)
                return false;

            return (permission.Level >= level);
        }


        private static bool HasAPTCABit(Assembly assembly)
        {
            return assembly.IsDefined(typeof(AllowPartiallyTrustedCallersAttribute), inherit: false);
        }

        internal static bool IsTypeAccessibleFromPartialTrust(Type t)
        {
            Assembly assembly = t.Assembly;

            if (assembly.SecurityRuleSet == SecurityRuleSet.Level1)
            {
                // Level 1 CAS uses transparency as an auditing mechanism rather than an enforcement mechanism, so we can't
                // perform a transparency check. Instead, allow the call to go through if:
                // (a) the referenced assembly is partially trusted, hence it cannot do anything dangerous; or
                // (b) the assembly is fully trusted and has APTCA.
                return (!assembly.IsFullyTrusted || HasAPTCABit(assembly));
            }
            else
            {
                // ** TEMPORARY **
                // Some GACed assemblies register critical modules / handlers. We can't break these scenarios for .NET 4.5, but we should
                // remove this APTCA check when we fix DevDiv #85358 and use only the transparency check defined below.
                if (HasAPTCABit(assembly))
                {
                    return true;
                }
                // ** END TEMPORARY **

                // Level 2 CAS uses transparency as an enforcement mechanism, so we can perform a transparency check.
                // Transparent and SafeCritical types are safe to use from partial trust code.
                return (t.IsSecurityTransparent || t.IsSecuritySafeCritical);
            }
        }


        /// <devdoc>
        ///    <para>Provides access to the cache.</para>
        /// </devdoc>
        public static Cache Cache
        {
            get
            {

                if (HttpRuntime.AspInstallDirectoryInternal == null)
                {
                    throw new HttpException(SR.GetString(SR.Aspnet_not_installed, VersionInfo.SystemWebVersion));
                }

                Cache cachePublic = _theRuntime._cachePublic;
                if (cachePublic == null)
                {
                    lock (_theRuntime)
                    {
                        cachePublic = _theRuntime._cachePublic;
                        if (cachePublic == null)
                        {
                            // Create the CACHE object
                            cachePublic = new Caching.Cache(0);
                            _theRuntime._cachePublic = cachePublic;
                        }
                    }
                }

                return cachePublic;
            }
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static string AspInstallDirectory
        {
            get
            {
                String path = AspInstallDirectoryInternal;

                if (path == null)
                {
                    throw new HttpException(SR.GetString(SR.Aspnet_not_installed, VersionInfo.SystemWebVersion));
                }

                InternalSecurityPermissions.PathDiscovery(path).Demand();
                return path;
            }
        }

        internal static string AspInstallDirectoryInternal
        {
            get { return s_installDirectory; }
        }

      
        internal static bool IsEngineLoaded
        {
            get { return s_isEngineLoaded; }
        }


        //
        //  Static app domain related properties
        //


        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static String CodegenDir
        {
            get
            {
                String path = CodegenDirInternal;
                InternalSecurityPermissions.PathDiscovery(path).Demand();
                return path;
            }
        }

        internal static string CodegenDirInternal
        {
            get { return _theRuntime._codegenDir; }
        }

        internal static string TempDirInternal
        {
            get { return _theRuntime._tempDir; }
        }


        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static String AppDomainAppId
        {
            get
            {
                return _theRuntime._appDomainAppId;
            }
        }

        internal static bool IsAspNetAppDomain
        {
            get { return AppDomainAppId != null; }
        }



        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static String AppDomainAppPath
        {
            get
            {
                InternalSecurityPermissions.AppPathDiscovery.Demand();
                return AppDomainAppPathInternal;
            }
        }

        internal static string AppDomainAppPathInternal
        {
            get { return _theRuntime._appDomainAppPath; }
        }


        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static String AppDomainAppVirtualPath
        {
            get
            {
                return VirtualPath.GetVirtualPathStringNoTrailingSlash(_theRuntime._appDomainAppVPath);
            }
        }

        // Save as AppDomainAppVirtualPath, but includes the trailng slash.  We can't change
        // AppDomainAppVirtualPath since it's public.
        internal static String AppDomainAppVirtualPathString
        {
            get
            {
                return VirtualPath.GetVirtualPathString(_theRuntime._appDomainAppVPath);
            }
        }

        internal static VirtualPath AppDomainAppVirtualPathObject
        {
            get
            {
                return _theRuntime._appDomainAppVPath;
            }
        }

        internal static bool IsPathWithinAppRoot(String path)
        {
            if (AppDomainIdInternal == null)
                return true;    // app domain not initialized

            return UrlPath.IsEqualOrSubpath(AppDomainAppVirtualPathString, path);
        }


        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static String AppDomainId
        {
            [AspNetHostingPermission(SecurityAction.Demand, Level = AspNetHostingPermissionLevel.High)]
            get
            {
                return AppDomainIdInternal;
            }
        }

        internal static string AppDomainIdInternal
        {
            get { return _theRuntime._appDomainId; }
        }



        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static String BinDirectory
        {
            get
            {
                String path = BinDirectoryInternal;
                InternalSecurityPermissions.PathDiscovery(path).Demand();
                return path;
            }
        }

        internal static string BinDirectoryInternal
        {
            get { return Path.Combine(_theRuntime._appDomainAppPath, BinDirectoryName) + Path.DirectorySeparatorChar; }

        }

        internal static VirtualPath CodeDirectoryVirtualPath
        {
            get { return _theRuntime._appDomainAppVPath.SimpleCombineWithDir(CodeDirectoryName); }
        }

        internal static VirtualPath ResourcesDirectoryVirtualPath
        {
            get { return _theRuntime._appDomainAppVPath.SimpleCombineWithDir(ResourcesDirectoryName); }
        }

        internal static VirtualPath WebRefDirectoryVirtualPath
        {
            get { return _theRuntime._appDomainAppVPath.SimpleCombineWithDir(WebRefDirectoryName); }
        }


        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public static bool IsOnUNCShare
        {
            [AspNetHostingPermission(SecurityAction.Demand, Level = AspNetHostingPermissionLevel.Low)]
            get
            {
                return IsOnUNCShareInternal;
            }
        }

        internal static bool IsOnUNCShareInternal
        {
            get { return _theRuntime._isOnUNCShare; }
        }


        //
        //  Static helper to retrieve app domain values
        //

        private static String GetAppDomainString(String key)
        {
            Object x = Thread.GetDomain().GetData(key);

            return x as String;
        }

        internal static void AddAppDomainTraceMessage(String message)
        {
            const String appDomainTraceKey = "ASP.NET Domain Trace";
            AppDomain d = Thread.GetDomain();
            String m = d.GetData(appDomainTraceKey) as String;
            d.SetData(appDomainTraceKey, (m != null) ? m + " ... " + message : message);
        }


    }
}
