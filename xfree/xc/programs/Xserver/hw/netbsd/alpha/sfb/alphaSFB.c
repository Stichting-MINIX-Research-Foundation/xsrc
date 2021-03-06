/* $NetBSD: alphaSFB.c,v 1.2 2011/05/24 23:10:03 jakllsch Exp $ */

/* $XConsortium: sunCfb.c,v 1.15.1.2 95/01/12 18:54:42 kaleb Exp $ */
/* $XFree86: xc/programs/Xserver/hw/sun/sunCfb.c,v 3.2 1995/02/12 02:36:22 dawes Exp $ */

/*
Copyright (c) 1990  X Consortium

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
X CONSORTIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the X Consortium shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from the X Consortium.
 */

/************************************************************
Copyright 1987 by Sun Microsystems, Inc. Mountain View, CA.

                    All Rights Reserved

Permission  to  use,  copy,  modify,  and  distribute   this
software  and  its documentation for any purpose and without
fee is hereby granted, provided that the above copyright no-
tice  appear  in all copies and that both that copyright no-
tice and this permission notice appear in  supporting  docu-
mentation,  and  that the names of Sun or X Consortium
not be used in advertising or publicity pertaining to 
distribution  of  the software  without specific prior 
written permission. Sun and X Consortium make no 
representations about the suitability of this software for 
any purpose. It is provided "as is" without any express or 
implied warranty.

SUN DISCLAIMS ALL WARRANTIES WITH REGARD TO  THIS  SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FIT-
NESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL SUN BE  LI-
ABLE  FOR  ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,  DATA  OR
PROFITS,  WHETHER  IN  AN  ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION  WITH
THE USE OR PERFORMANCE OF THIS SOFTWARE.

********************************************************/

/*
 * Copyright (c) 1987 by the Regents of the University of California
 * Copyright (c) 1987 by Adam de Boor, UC Berkeley
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies.  The University of California
 * makes no representations about the suitability of this
 * software for any purpose.  It is provided "as is" without
 * express or implied warranty.
 */

/****************************************************************/
/* Modified from  sunCG4C.c for X11R3 by Tom Jarmolowski	*/
/****************************************************************/

/* 
 * Copyright 1991, 1992, 1993 Kaleb S. Keithley
 *
 * Permission to use, copy, modify, and distribute this
 * software and its documentation for any purpose and without
 * fee is hereby granted, provided that the above copyright
 * notice appear in all copies.  Kaleb S. Keithley makes no 
 * representations about the suitability of this software for 
 * any purpose.  It is provided "as is" without express or 
 * implied warranty.
 */

#include "alpha.h"
#include "cfb.h"
#include "cfb32.h"
#include <dev/tc/sfbreg.h>

/* XXX */
#include <stdio.h>

static Bool alphaSfbScreenInit(
    register ScreenPtr, pointer, int, int, int, int, int, int);

static void CGUpdateColormap(pScreen, dex, count, rmap, gmap, bmap)
    ScreenPtr	pScreen;
    int		dex, count;
    u_char	*rmap, *gmap, *bmap;
{
#ifdef USE_WSCONS
    struct wsdisplay_cmap alphaCmap;
#else
    struct fbcmap alphaCmap;
#endif

    alphaCmap.index = dex;
    alphaCmap.count = count;
    alphaCmap.red = &rmap[dex];
    alphaCmap.green = &gmap[dex];
    alphaCmap.blue = &bmap[dex];

#ifdef USE_WSCONS
    if (ioctl(alphaFbs[pScreen->myNum].fd, WSDISPLAYIO_PUTCMAP, &alphaCmap) < 0) {
	Error("CGUpdateColormap");
	FatalError( "CGUpdateColormap: FBIOPUTCMAP failed\n" );
    }
#else
    if (ioctl(alphaFbs[pScreen->myNum].fd, FBIOPUTCMAP, &alphaCmap) < 0) {
	Error("CGUpdateColormap");
	FatalError( "CGUpdateColormap: FBIOPUTCMAP failed\n" );
    }
#endif
}

void alphaSfbInstallColormap(cmap)
    ColormapPtr	cmap;
{
    SetupScreen(cmap->pScreen);
    register int i;
    register Entry *pent;
    register VisualPtr pVisual = cmap->pVisual;
    u_char	  rmap[256], gmap[256], bmap[256];
    unsigned long rMask, gMask, bMask;
    int	oRed, oGreen, oBlue;

    if (cmap == pPrivate->installedMap)
	return;
    if (pPrivate->installedMap)
	WalkTree(pPrivate->installedMap->pScreen, TellLostMap,
		 (pointer) &(pPrivate->installedMap->mid));
    if ((pVisual->class | DynamicClass) == DirectColor) {
	if (pVisual->ColormapEntries < 256) {
	    rMask = pVisual->redMask;
	    gMask = pVisual->greenMask;
	    bMask = pVisual->blueMask;
	    oRed = pVisual->offsetRed;
	    oGreen = pVisual->offsetGreen;
	    oBlue = pVisual->offsetBlue;
	} else {
	    rMask = gMask = bMask = 255;
	    oRed = oGreen = oBlue = 0;
	}
	for (i = 0; i < 256; i++) {
	    rmap[i] = cmap->red[(i & rMask) >> oRed].co.local.red >> 8;
	    gmap[i] = cmap->green[(i & gMask) >> oGreen].co.local.green >> 8;
	    bmap[i] = cmap->blue[(i & bMask) >> oBlue].co.local.blue >> 8;
	}
    } else {
	for (i = 0, pent = cmap->red;
	     i < pVisual->ColormapEntries;
	     i++, pent++) {
	    if (pent->fShared) {
		rmap[i] = pent->co.shco.red->color >> 8;
		gmap[i] = pent->co.shco.green->color >> 8;
		bmap[i] = pent->co.shco.blue->color >> 8;
	    }
	    else {
		rmap[i] = pent->co.local.red >> 8;
		gmap[i] = pent->co.local.green >> 8;
		bmap[i] = pent->co.local.blue >> 8;
	    }
	}
    }
    pPrivate->installedMap = cmap;
    (*pPrivate->UpdateColormap) (cmap->pScreen, 0, 256, rmap, gmap, bmap);
    WalkTree(cmap->pScreen, TellGainedMap, (pointer) &(cmap->mid));
}

void alphaSfbUninstallColormap(cmap)
    ColormapPtr	cmap;
{
    SetupScreen(cmap->pScreen);
    if (cmap == pPrivate->installedMap) {
	Colormap defMapID = cmap->pScreen->defColormap;

	if (cmap->mid != defMapID) {
	    ColormapPtr defMap = (ColormapPtr) LookupIDByType(defMapID,
							      RT_COLORMAP);

	    if (defMap)
		(*cmap->pScreen->InstallColormap)(defMap);
	    else
	        ErrorF("alphaFbs: Can't find default colormap\n");
	}
    }
}

int alphaSfbListInstalledColormaps(pScreen, pCmapList)
    ScreenPtr	pScreen;
    Colormap	*pCmapList;
{
    SetupScreen(pScreen);
    *pCmapList = pPrivate->installedMap->mid;
    return (1);
}

static void CGStoreColors(pmap, ndef, pdefs)
    ColormapPtr	pmap;
    int		ndef;
    xColorItem	*pdefs;
{
    SetupScreen(pmap->pScreen);
    u_char	rmap[256], gmap[256], bmap[256];
    xColorItem	expanddefs[256];
    register int i;

    if (pPrivate->installedMap != NULL && pPrivate->installedMap != pmap)
	return;
    if ((pmap->pVisual->class | DynamicClass) == DirectColor) {
	ndef = cfbExpandDirectColors(pmap, ndef, pdefs, expanddefs);
	pdefs = expanddefs;
    }
    while (ndef--) {
	i = pdefs->pixel;
	rmap[i] = pdefs->red >> 8;
	gmap[i] = pdefs->green >> 8;
	bmap[i] = pdefs->blue >> 8;
	(*pPrivate->UpdateColormap) (pmap->pScreen, i, 1, rmap, gmap, bmap);
	pdefs++;
    }
}

static void CGScreenInit (pScreen)
    ScreenPtr	pScreen;
{
#ifndef STATIC_COLOR /* { */
    SetupScreen (pScreen);
    pScreen->InstallColormap = alphaSfbInstallColormap;
    pScreen->UninstallColormap = alphaSfbUninstallColormap;
    pScreen->ListInstalledColormaps = alphaSfbListInstalledColormaps;
    pScreen->StoreColors = CGStoreColors;
    pPrivate->UpdateColormap = CGUpdateColormap;
    if (/*alphaFlipPixels ||*/ 1) {			/* XXX */
	Pixel pixel = pScreen->whitePixel;
	pScreen->whitePixel = pScreen->blackPixel;
	pScreen->blackPixel = pixel;
    }
#endif /* } */
}

/*
 * Restore color map to white-on-black, and call alphaCloseScreen
 */
static Bool
alphaSfbCloseScreen (i, pScreen)
    int i;
    ScreenPtr pScreen;
{
    SetupScreen(pScreen);
    u_char greymap[256];
  
    memset(greymap, 0xff, 256);
    greymap[0] = 0;

    (*pPrivate->UpdateColormap) (pScreen, 0, 256, greymap, greymap, greymap);
    return alphaCloseScreen(i, pScreen);
}

Bool alphaSFBInit (screen, pScreen, argc, argv)
    int	    	  screen;    	/* what screen am I going to be */
    ScreenPtr	  pScreen;  	/* The Screen to initialize */
    int	    	  argc;	    	/* The number of the Server's arguments. */
    char    	  **argv;   	/* The arguments themselves. Don't change! */
{
	unsigned char *fb = fb = alphaFbs[screen].fb;
	unsigned char *fbr;
	int fb_off, realwidth, rowsize;
	volatile sfb_reg_t *sfbregs;

	alphaFbs[screen].EnterLeave = (void (*)())NoopDDA;

    	if (!alphaScreenAllocate(pScreen))
		return FALSE;
	if (!fb) {
		if ((fb = alphaMemoryMap ((size_t)alphaFbs[screen].size,
		    0, alphaFbs[screen].fd)) == NULL)
			return FALSE;
	        alphaFbs[screen].fb = fb;
	}

	/*
	 * Frame buffer RAM always starts at core space size / 2.
	 * SFB Registers always start at offset 1M into core space.
	 *
	 * The actual offset of the displayed screen may vary, because
	 * of cursor ram location.  Also, pixel-width of the frame buffer
	 * may not be the same as the displayed width.  To figure these
	 * things out, we have to look at the SFB registers.
	 */ 
	sfbregs = (sfb_reg_t *)(fb + (1 * 1024 * 1024));
	fb_off = (int)alphaFbs[screen].size / 2;
	fbr = fb + ( 1 * 1024 * 1024 );
	alphaFbs[screen].regs.sfbregs[0] = (sfb_reg_t *)(fbr + 0 * 64 * 1024);
	alphaFbs[screen].regs.sfbregs[1] = (sfb_reg_t *)(fbr + 1 * 64 * 1024);
	alphaFbs[screen].regs.sfbregs[2] = (sfb_reg_t *)(fbr + 2 * 64 * 1024);
	alphaFbs[screen].regs.sfbregs[3] = (sfb_reg_t *)(fbr + 3 * 64 * 1024);

	/* Find out real pixel width of the display. */
	realwidth = (sfbregs[SFB_REG_VHCR] & 0x1ff) * 4;

	/*
	 * Find out how big one 'row' of video is, so that we can tell
	 * where the displayed frame buffer actually starts.
	 */
	rowsize = 2 * 1024;			/* 2k for 128K VRAMs, 8BPP */
	if (alphaFbs[screen].info.depth == 32)
		rowsize *= 4;			/* increase by 4x for 32BPP */
	if ((sfbregs[SFB_REG_GDER] & 0x200) == 0) /* 256K VRAMs */
		rowsize *= 2;			/* increase by 2x */

	/*
	 * Finally, calcluate real displayed frame buffer offset.
	 */
#if 0	/* VVBR is write only, but we always write it as 1. */
	fb_off += rowsize * (sfbregs[SFB_REG_VVBR] & 0x1ff);
#else
	fb_off += rowsize * 1;
#endif

	if (!alphaSfbScreenInit(pScreen, fb + fb_off,
	    alphaFbs[screen].info.width,
	    alphaFbs[screen].info.height,
	    monitorResolution, monitorResolution,
	    realwidth,
	    alphaFbs[screen].info.depth)) {
fprintf(stderr, "alphaSfbScreenInit failed\n");
            return FALSE;
	}

	CGScreenInit(pScreen);
	if (!alphaScreenInit(pScreen)) {
fprintf(stderr, "alphaScreenInit failed\n");
		return FALSE;
	}
	pScreen->CloseScreen = alphaSfbCloseScreen;
	(void) alphaSaveScreen(pScreen, SCREEN_SAVER_OFF);
	return cfbCreateDefColormap(pScreen);
}

Bool
alphaSfbSetupScreen(pScreen, pbits, xsize, ysize, dpix, dpiy, width, bpp)
    register ScreenPtr pScreen;
    pointer pbits;		/* pointer to screen bitmap */
    int xsize, ysize;		/* in pixels */
    int dpix, dpiy;		/* dots per inch */
    int width;			/* pixel width of frame buffer */
    int	bpp;			/* bits per pixel of root */
{
    switch (bpp) {
    case 32:
	if (!cfb32SetupScreen(pScreen, pbits, xsize, ysize, dpix, dpiy,
	  width))
	    return FALSE;
	return cfbSetVisualTypes(24, 1 << TrueColor, 8);
    case 8:
	if (!cfbSetupScreen(pScreen, pbits, xsize, ysize, dpix, dpiy,
	  width))
	    return FALSE;
	if (alphaSfbAccelerate) {
	    pScreen->CopyWindow = alphaSfbCopyWindow;
	    pScreen->CreateGC = alphaSfbCreateGC;
	}
	return TRUE;
    default:
	fprintf(stderr, "alphaSfbSetupScreen:  unsupported bpp = %d\n", bpp);
	return FALSE;
    }
}

Bool
alphaSfbFinishScreenInit(pScreen, pbits, xsize, ysize, dpix, dpiy, width, bpp)
    register ScreenPtr pScreen;
    pointer pbits;		/* pointer to screen bitmap */
    int xsize, ysize;		/* in pixels */
    int dpix, dpiy;		/* dots per inch */
    int width;			/* pixel width of frame buffer */
    int bpp;			/* bits per pixel of root */
{
    Bool retval;

    switch (bpp) {
    case 32:
	retval = cfb32FinishScreenInit(pScreen, pbits, xsize, ysize,
		    dpix, dpiy, width);

	/* XXXNJW cfb doesn't provide a way to tweak these, so cheat. */
	pScreen->visuals[0].redMask = 0xff0000;
	pScreen->visuals[0].greenMask = 0xff00;
	pScreen->visuals[0].blueMask = 0xff;

	pScreen->visuals[0].offsetRed = 16;
	pScreen->visuals[0].offsetGreen = 8;
	pScreen->visuals[0].offsetBlue = 0;

	break;
    case 8:
	retval = cfbFinishScreenInit(pScreen, pbits, xsize, ysize,
		    dpix, dpiy, width);
	break;
    default:
	retval = FALSE;
    }

    return retval;
}

Bool
alphaSfbScreenInit(pScreen, pbits, xsize, ysize, dpix, dpiy, width, bpp)
    register ScreenPtr pScreen;
    pointer pbits;		/* pointer to screen bitmap */
    int xsize, ysize;		/* in pixels */
    int dpix, dpiy;		/* dots per inch */
    int width;			/* pixel width of frame buffer */
    int bpp;			/* bits per pixel of root */
{
    if (!alphaSfbSetupScreen(pScreen, pbits, xsize, ysize, dpix,
	dpiy, width, bpp))
	    return FALSE;
    return alphaSfbFinishScreenInit(pScreen, pbits, xsize, ysize, dpix,
	  dpiy, width, bpp);
}
