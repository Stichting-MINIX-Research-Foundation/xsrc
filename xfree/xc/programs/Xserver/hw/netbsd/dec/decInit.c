/* $NetBSD: decInit.c,v 1.3 2011/05/24 21:21:55 jakllsch Exp $ */

#include    "dec.h"
#include    "gcstruct.h"
/* #include    "mi.h" */
#include    "mibstore.h"
#include    "cfb.h"

#include <stdio.h>
#include <err.h>

Bool decTGAInit(int, ScreenPtr, int, char **);
Bool decSFBInit(int, ScreenPtr, int, char **);
Bool decCFBInit(int, ScreenPtr, int, char **);
Bool decMFBInit(int, ScreenPtr, int, char **);
Bool decPXInit(int, ScreenPtr, int, char **);

static Bool	decDevsInited = FALSE;

decKbdPrivRec decKbdPriv = {
    -1,		/* fd */
    -1,		/* type */
    -1,		/* layout */
    0,		/* click */
    (Leds)0,	/* leds */
    0,		/* prevClick */
    { -1, -1, -1, -1, -1, -1, -1, -1 }, /* keys_down */
};

decPtrPrivRec decPtrPriv = {
    -1,		/* fd */
    0		/* Current button state */
};

decFbDataRec decFbData[] = {
    { WSDISPLAY_TYPE_MFB,	TRUE,	"MX (MFB)",	decCFBInit },
    { WSDISPLAY_TYPE_SFB,	TRUE,	"HX (SFB)",	decSFBInit },
    { WSDISPLAY_TYPE_SFBP,	TRUE,	"HX+ (SFB+)",	decSFBInit },
    { WSDISPLAY_TYPE_CFB,	TRUE,	"CX (CFB)",	decCFBInit },
    { WSDISPLAY_TYPE_TX,	TRUE,	"TX (TFB)",	decCFBInit },
    { WSDISPLAY_TYPE_PX,	FALSE,	"PX",		decPXInit  },
    { WSDISPLAY_TYPE_PXG,	FALSE,	"PXG",		decPXInit },

#if defined(__alpha__)

    { WSDISPLAY_TYPE_TGA,	TRUE,	"TGA",		decTGAInit, },

#else

    { WSDISPLAY_TYPE_PM_MONO,	FALSE,	"PM (mono)",	decMFBInit, },
    { WSDISPLAY_TYPE_PM_COLOR,	FALSE,	"PM (color)",	decCFBInit, },
    { WSDISPLAY_TYPE_XCFB,	TRUE,	"XCFB",		decCFBInit, },
    { WSDISPLAY_TYPE_VAX_MONO,	FALSE,	"SMG",		decMFBInit, },

#endif
};

/*
 * a list of devices to try if there is no environment or command
 * line list of devices
 */
static char *fallbackList[] = {
    "/dev/ttyE0", "/dev/ttyE1", "/dev/ttyE2", "/dev/ttyE3",
    "/dev/ttyE4", "/dev/ttyE5", "/dev/ttyE6", "/dev/ttyE7",
};
#define FALLBACK_LIST_LEN sizeof fallbackList / sizeof fallbackList[0]

fbFd decFbs[MAXSCREENS];
Bool decSoftCursor = 0;
Bool decHardCursor = 0;
Bool decAccelerate = 1;
int decWantedDepth = 0;
char *decKbdDev;
char *decPtrDev;

static PixmapFormatRec	formats[] = {
    { 1, 1, BITMAP_SCANLINE_PAD},
    { 8, 8, BITMAP_SCANLINE_PAD},	/* 8-bit deep */
    { 24, 32, BITMAP_SCANLINE_PAD}	/* 32-bit deep */
};
#define NUMFORMATS	(sizeof formats)/(sizeof formats[0])

#ifdef notyet
static PixmapFormatRec	formats32[] = {
    { 1, 1, BITMAP_SCANLINE_PAD},
    { 24, 32, BITMAP_SCANLINE_PAD}	/* 32-bit deep */
};
#define NUMFORMATS32	(sizeof formats32)/(sizeof formats32[0])
#endif

/*
 * OpenFrameBuffer --
 *	Open a frame buffer according to several rules.
 *	Find the device to use by looking in the decFbData table,
 *	an XDEVICE envariable, or a -dev switch.
 *
 * Results:
 *	The fd of the framebuffer.
 */
static int OpenFrameBuffer(device, screen)
    char		*device;	/* e.g. "/dev/ttyE0" */
    int			screen;    	/* what screen am I going to be */
{
    int			ret = TRUE;
    struct		wsdisplay_fbinfo info;
    int			type;
    int			i;

    decFbs[screen].fd = -1;
    if (access (device, R_OK | W_OK) == -1)
	return FALSE;
    if ((decFbs[screen].fd = open(device, O_RDWR, 0)) == -1)
	ret = FALSE;
    else {
	if (ioctl(decFbs[screen].fd, WSDISPLAYIO_GTYPE, &type) == -1) {
		Error("unable to get frame buffer type");
		(void) close(decFbs[screen].fd);
		decFbs[screen].fd = -1;
		ret = FALSE; 
	}
	if (ioctl(decFbs[screen].fd, WSDISPLAYIO_GINFO,
	    &info) == -1) {
		Error("unable to get frame buffer info");
		(void) close(decFbs[screen].fd);
		decFbs[screen].fd = -1;
		ret = FALSE; 
	}
	decFbs[screen].type = type;
	decFbs[screen].height = info.height;
	decFbs[screen].width = info.width;
	decFbs[screen].depth = info.depth;
	decFbs[screen].cmsize = info.cmsize;
	if (decFbs[screen].depth == 32)
		decFbs[screen].size = 16*1024*1024; /* XXXNJW */
	else
		decFbs[screen].size = 4*1024*1024;
	if (ret) {
	    decFbs[screen].fbData = NULL;

	    for (i = 0; i < sizeof(decFbData) / sizeof(decFbData[0]); i++)
	        if (decFbData[i].type == type) {
	            decFbs[screen].fbData = &decFbData[i];
	            break;
	        }

	    if (decFbs[screen].fbData == NULL) {
		    Error("frame buffer type not supported");
		    (void) close(decFbs[screen].fd);
		    decFbs[screen].fd = -1;
		    ret = FALSE;
	    }
	}
    }
    if (!ret)
	decFbs[screen].fd = -1;
    return ret;
}

/*-
 *-----------------------------------------------------------------------
 * SigIOHandler --
 *	Signal handler for SIGIO - input is available.
 *
 * Results:
 *	decSigIO is set - ProcessInputEvents() will be called soon.
 *
 * Side Effects:
 *	None
 *
 *-----------------------------------------------------------------------
 */
/*ARGSUSED*/
static void SigIOHandler(sig)
    int		sig;
{
    int olderrno = errno;
    decEnqueueEvents ();
    errno = olderrno;
}

static char** GetDeviceList (argc, argv)
    int		argc;
    char	**argv;
{
    int		i;
    char	*envList = NULL;
    char	*cmdList = NULL;
    char	**deviceList = (char **)NULL; 

    for (i = 1; i < argc; i++)
	if (strcmp (argv[i], "-dev") == 0 && i+1 < argc) {
	    cmdList = argv[i + 1];
	    break;
	}
    if (!cmdList)
	envList = getenv ("XDEVICE");

    if (cmdList || envList) {
	char	*_tmpa;
	char	*_tmpb;
	int	_i1;
	deviceList = (char **) xalloc ((MAXSCREENS + 1) * sizeof (char *));
	_tmpa = (cmdList) ? cmdList : envList;
	for (_i1 = 0; _i1 < MAXSCREENS; _i1++) {
	    _tmpb = strtok (_tmpa, ":");
	    if (_tmpb)
		deviceList[_i1] = _tmpb;
	    else
		deviceList[_i1] = NULL;
	    _tmpa = NULL;
	}
	deviceList[MAXSCREENS] = NULL;
    }
    if (!deviceList) {
	/* no environment and no cmdline, so default */
	deviceList = 
	    (char **) xalloc ((FALLBACK_LIST_LEN + 1) * sizeof (char *));
	for (i = 0; i < FALLBACK_LIST_LEN; i++)
	    deviceList[i] = fallbackList[i];
	deviceList[FALLBACK_LIST_LEN] = NULL;
    }
    return deviceList;
}

void OsVendorPreInit(
#if NeedFunctionPrototypes
    void
#endif
)
{
}
void OsVendorInit(
#if NeedFunctionPrototypes
    void
#endif
)
{
    static int inited;
    struct rlimit rl;

    if (!inited) {

	/* 
	 * one per client, one per screen, one per listen endpoint,
	 * keyboard, mouse, and stderr
	 */
	int maxfds = MAXCLIENTS + MAXSCREENS + 5;

	if (getrlimit (RLIMIT_NOFILE, &rl) == 0) {
	    rl.rlim_cur = maxfds < rl.rlim_max ? maxfds : rl.rlim_max;
	    (void) setrlimit (RLIMIT_NOFILE, &rl);
	}
	inited = 1;
    }
}

static void
InitKbdMouse(void)
{
    static int inited;
    int i;

    if (inited)
        return;
    inited = 1;

    if (decKbdDev == NULL)
        decKbdDev = "/dev/wskbd0";
    if (decPtrDev == NULL)
       decPtrDev = "/dev/wsmouse0";

    /* warn(3) isn't X11 API, but we know we are on NetBSD */
    if((decKbdPriv.fd = open (decKbdDev, O_RDWR, 0)) == -1)
	warn("Keyboard device %s", decKbdDev);
    else if((decPtrPriv.fd = open (decPtrDev, O_RDWR, 0)) == -1)
	warn("Pointer device %s", decPtrDev);
    (void) ioctl (decKbdPriv.fd, WSKBDIO_GTYPE, &decKbdPriv.type);
}

/*-
 *-----------------------------------------------------------------------
 * InitOutput --
 *	Initialize screenInfo for all actually accessible framebuffers.
 *	The
 *
 * Results:
 *	screenInfo init proc field set
 *
 * Side Effects:
 *	None
 *
 *-----------------------------------------------------------------------
 */

void InitOutput(pScreenInfo, argc, argv)
    ScreenInfo 	  *pScreenInfo;
    int     	  argc;
    char    	  **argv;
{
    int     	i, scr;
    int		nonBlockConsole = 0;
    char	**devList;
    static int	setup_on_exit = 0;
    extern Bool	RunFromSmartParent;

    if (!monitorResolution)
	monitorResolution = 90;
    if (RunFromSmartParent)
	nonBlockConsole = 1;
    for (i = 1; i < argc; i++) {
	if (!strcmp(argv[i],"-debug"))
	    nonBlockConsole = 0;
    }

    pScreenInfo->imageByteOrder = IMAGE_BYTE_ORDER;
    pScreenInfo->bitmapScanlineUnit = BITMAP_SCANLINE_UNIT;
    pScreenInfo->bitmapScanlinePad = BITMAP_SCANLINE_PAD;
    pScreenInfo->bitmapBitOrder = BITMAP_BIT_ORDER;

    pScreenInfo->numPixmapFormats = NUMFORMATS;
    for (i=0; i< NUMFORMATS; i++)
        pScreenInfo->formats[i] = formats[i];
#if 0 /* XXX */
#ifdef XKB
    if (noXkbExtension)
#endif
    sunAutoRepeatHandlersInstalled = FALSE;
#endif
    if (!decDevsInited) {
	/* first time ever */
	for (scr = 0; scr < MAXSCREENS; scr++)
	    decFbs[scr].fd = -1;
	devList = GetDeviceList (argc, argv);
	for (i = 0, scr = 0; devList[i] != NULL && scr < MAXSCREENS; i++)
	    if (OpenFrameBuffer (devList[i], scr))
		scr++;
	decDevsInited = TRUE;
	xfree (devList);
    }
    for (scr = 0; scr < MAXSCREENS; scr++)
	if (decFbs[scr].fd != -1) {
	    ErrorF("XdecNetBSD: screen %d: %s, %dx%d\n", scr,
	        decFbs[scr].fbData->name, decFbs[scr].width,
	        decFbs[scr].height);
	    (void) AddScreen (decFbs[scr].fbData->init, argc, argv);
	}
    (void) OsSignal(SIGWINCH, SIG_IGN);
}

/*-
 *-----------------------------------------------------------------------
 * InitInput --
 *	Initialize all supported input devices...what else is there
 *	besides pointer and keyboard?
 *
 * Results:
 *	None.
 *
 * Side Effects:
 *	Two DeviceRec's are allocated and registered as the system pointer
 *	and keyboard devices.
 *
 *-----------------------------------------------------------------------
 */
void InitInput(argc, argv)
    int     	  argc;
    char    	  **argv;
{
    DeviceIntPtr	p, k;
    extern Bool mieqInit();

    InitKbdMouse();

    p = AddInputDevice(decMouseProc, TRUE);
    k = AddInputDevice(decKbdProc, TRUE);
    if (!p || !k)
	FatalError("failed to create input devices in InitInput");

    RegisterPointerDevice(p);
    RegisterKeyboardDevice(k);
    miRegisterPointerDevice(screenInfo.screens[0], p);
    (void) mieqInit (k, p);
#define SET_FLOW(fd) fcntl(fd, F_SETFL, FNDELAY | FASYNC)
    (void) OsSignal(SIGIO, SigIOHandler);
#define WANT_SIGNALS(fd) fcntl(fd, F_SETOWN, getpid())
    if (decKbdPriv.fd >= 0) {
	if (SET_FLOW(decKbdPriv.fd) == -1 || WANT_SIGNALS(decKbdPriv.fd) == -1) {	
	    (void) close (decKbdPriv.fd);
	    decKbdPriv.fd = -1;
	    FatalError("Async kbd I/O failed in InitInput");
	}
    }
    if (decPtrPriv.fd >= 0) {
	if (SET_FLOW(decPtrPriv.fd) == -1 || WANT_SIGNALS(decPtrPriv.fd) == -1) {	
#if 0
	    (void) close (decPtrPriv.fd);
	    decPtrPriv.fd = -1;
	    FatalError("Async mouse I/O failed in InitInput");
#endif
	    ErrorF("Async mouse I/O failed in InitInput");
	}
    }
}


/*#ifdef DDXOSFATALERROR*/
void OsVendorFatalError(void)
{
}
/*#endif*/

#ifdef DPMSExtension
/**************************************************************
 * DPMSSet(), DPMSGet(), DPMSSupported()
 *
 * stubs
 *
 ***************************************************************/

void DPMSSet (level)
    int level;
{
}

int DPMSGet (level)
    int* level;
{
    return -1;
}

Bool DPMSSupported ()
{
    return FALSE;
}
#endif
