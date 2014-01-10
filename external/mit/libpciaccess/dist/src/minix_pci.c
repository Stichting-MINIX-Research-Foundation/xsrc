#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/ttycom.h>
#include <sys/video.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dev/pci/pcidevs.h>
#include <dev/pci/pciio.h>
#include <dev/pci/pcireg.h>

#include <pci.h>

#include "pciaccess.h"
#include "pciaccess_private.h"

static int nbuses = 1;

static struct {
    int pci_fd;
} _state;


static int
pci_read(int domain, int bus, int dev, int func, uint32_t reg, uint32_t *val)
{
	uint32_t rval;

	if ((domain < 0) || (domain > nbuses))
		return -1;

#if 0
	if (pcibus_conf_read(buses[domain].fd, (unsigned int)bus,
#else
	if (pcibus_conf_read(_state.pci_fd, (unsigned int)bus,
#endif
	    (unsigned int)dev, (unsigned int)func, reg, &rval) == -1)
		return (-1);

	*val = rval;

	return 0;
}

static int
pci_write(int domain, int bus, int dev, int func, uint32_t reg, uint32_t val)
{

	if ((domain < 0) || (domain > nbuses))
		return -1;

#if 0
	return pcibus_conf_write(buses[domain].fd, (unsigned int)bus,
#else
	return pcibus_conf_write(_state.pci_fd, (unsigned int)bus,
#endif
	    (unsigned int)dev, (unsigned int)func, reg, val);
}

static int
pci_nfuncs(int domain, int bus, int dev)
{
	uint32_t hdr;

	if ((domain < 0) || (domain > nbuses))
		return -1;

	if (pci_read(domain, bus, dev, 0, PCI_BHLC_REG, &hdr) != 0)
		return -1;

	return (PCI_HDRTYPE_MULTIFN(hdr) ? 8 : 1);
}

/*ARGSUSED*/
static int
pci_device_minix_map_range(struct pci_device *dev,
    struct pci_device_mapping *map)
{
#ifdef HAVE_MTRR
	struct mtrr m;
	int n = 1;
#endif
	int prot, ret = 0;

	prot = PROT_READ;

	if (map->flags & PCI_DEV_MAP_FLAG_WRITABLE)
		prot |= PROT_WRITE;
#if 0
	map->memory = mmap(NULL, (size_t)map->size, prot, MAP_SHARED,
	    buses[dev->domain].fd, (off_t)map->base);
#else
	{
		struct pciio_map _map;
		int r;
		_map.flags = 0;
		_map.phys_offset = map->base;
		_map.size = map->size;
		_map.readonly = (map->flags & PCI_DEV_MAP_FLAG_WRITABLE) != PCI_DEV_MAP_FLAG_WRITABLE;

		r = ioctl(_state.pci_fd, PCI_IOC_MAP, &_map);
		map->memory = _map.vaddr_ret;
		if (r < 0) {
			map->memory = MAP_FAILED;
		}
	}
#endif
	if (map->memory == MAP_FAILED)
		return errno;

#ifdef HAVE_MTRR
	memset(&m, 0, sizeof(m));

	/* No need to set an MTRR if it's the default mode. */
	if ((map->flags & PCI_DEV_MAP_FLAG_CACHABLE) ||
	    (map->flags & PCI_DEV_MAP_FLAG_WRITE_COMBINE)) {
		m.base = map->base;
		m.flags = MTRR_VALID | MTRR_PRIVATE;
		m.len = map->size;
		m.owner = getpid();
		if (map->flags & PCI_DEV_MAP_FLAG_CACHABLE)
			m.type = MTRR_TYPE_WB;
		if (map->flags & PCI_DEV_MAP_FLAG_WRITE_COMBINE)
			m.type = MTRR_TYPE_WC;

		if ((netbsd_set_mtrr(&m, &n)) == -1) {
			fprintf(stderr, "mtrr set failed: %s\n",
			    strerror(errno));
		}
	}
#endif

	return ret;
}

static int
pci_device_minix_unmap_range(struct pci_device *dev,
    struct pci_device_mapping *map)
{
#ifdef HAVE_MTRR
	struct mtrr m;
	int n = 1;

	memset(&m, 0, sizeof(m));

	if ((map->flags & PCI_DEV_MAP_FLAG_CACHABLE) ||
	    (map->flags & PCI_DEV_MAP_FLAG_WRITE_COMBINE)) {
		m.base = map->base;
		m.flags = 0;
		m.len = map->size;
		m.type = MTRR_TYPE_UC;
		(void)netbsd_set_mtrr(&m, &n);
	}
#endif

#if 0
	return pci_device_generic_unmap_range(dev, map);
#else
	{
		struct pciio_map _map;
		_map.size = map->size;
		_map.vaddr = map->memory;

		return ioctl(_state.pci_fd, PCI_IOC_UNMAP, &_map);
	}
#endif
}

static int
pci_device_minix_read(struct pci_device *dev, void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_read)
{
	u_int reg, rval;

	*bytes_read = 0;
	while (size > 0) {
		size_t toread = MIN(size, 4 - (offset & 0x3));

		reg = (u_int)(offset & ~0x3);

#if 0
		if ((pcibus_conf_read(buses[dev->domain].fd,
#else
		if ((pcibus_conf_read(_state.pci_fd,
#endif
		    (unsigned int)dev->bus, (unsigned int)dev->dev,
		    (unsigned int)dev->func, reg, &rval)) == -1)
			return errno;

		rval = htole32(rval);
		rval >>= ((offset & 0x3) * 8);

		memcpy(data, &rval, toread);

		offset += toread;
		data = (char *)data + toread;
		size -= toread;
		*bytes_read += toread;
	}

	return 0;
}

static int
pci_device_minix_write(struct pci_device *dev, const void *data,
    pciaddr_t offset, pciaddr_t size, pciaddr_t *bytes_written)
{
	u_int reg, val;

	if ((offset % 4) != 0 || (size % 4) != 0)
		return EINVAL;

	*bytes_written = 0;
	while (size > 0) {
		reg = (u_int)offset;
		memcpy(&val, data, 4);

#if 0
		if ((pcibus_conf_write(buses[dev->domain].fd,
#else
		if ((pcibus_conf_write(_state.pci_fd,
#endif
		    (unsigned int)dev->bus, (unsigned int)dev->dev,
		    (unsigned int)dev->func, reg, val)) == -1)
			return errno;

		offset += 4;
		data = (const char *)data + 4;
		size -= 4;
		*bytes_written += 4;
	}

	return 0;
}

static int
pci_device_minix_boot_vga(struct pci_device *dev)
{
	/*FIXME: This should check this is the vga device used by the console*/
	return 0;
}

static int
pci_device_minix_map_legacy(struct pci_device *dev, pciaddr_t base,
				  pciaddr_t size, unsigned map_flags, void **addr)
{
	struct pci_device_mapping map;
	int err;

	map.base = base;
	map.size = size;
	map.flags = map_flags;
	map.memory = NULL;
	err = pci_device_minix_map_range(dev, &map);
	*addr = map.memory;

	return err;
}

static int
pci_device_minix_unmap_legacy(struct pci_device *dev, void *addr, pciaddr_t size)
{
	struct pci_device_mapping map;

	map.memory = addr;
	map.size = size;
	map.flags = 0;
	return pci_device_minix_unmap_range(dev, &map);
}


static void
pci_system_minix_destroy(void)
{
	free(pci_sys->devices);
	free(pci_sys);
	close(_state.pci_fd);
}

static void
pci_system_minix_destroy_device( struct pci_device *dev)
{
	int r;
	struct pciio_acl acl;
	acl.domain = dev->domain;
	acl.bus = dev->bus;
	acl.device = dev->dev;
	acl.function = dev->func;

	r = ioctl(_state.pci_fd, PCI_IOC_RELEASE, &acl);
	if (r < 0)
		fprintf(stderr, "%s:%d PCI release failed r = %d\n", __func__, __LINE__, r);
}

static int
pci_device_minix_probe(struct pci_device *device)
{
	struct pci_device_private *priv =
	    (struct pci_device_private *)(void *)device;
	struct pci_mem_region *region;
	uint64_t reg64, size64;
	uint32_t bar, reg, size;
	int bus, dev, func, err, domain;

	domain = device->domain;
	bus = device->bus;
	dev = device->dev;
	func = device->func;

	/* Enable the device if necessary */
	err = pci_read(domain, bus, dev, func, PCI_COMMAND_STATUS_REG, &reg);
	if (err)
		return err;
	if ((reg & (PCI_COMMAND_IO_ENABLE | PCI_COMMAND_MEM_ENABLE | PCI_COMMAND_MASTER_ENABLE)) !=
	    (PCI_COMMAND_IO_ENABLE | PCI_COMMAND_MEM_ENABLE | PCI_COMMAND_MASTER_ENABLE)) {
		reg |= PCI_COMMAND_IO_ENABLE |
		       PCI_COMMAND_MEM_ENABLE |
		       PCI_COMMAND_MASTER_ENABLE;
		err = pci_write(domain, bus, dev, func, PCI_COMMAND_STATUS_REG,
				reg);
		if (err)
			return err;
	}

	err = pci_read(domain, bus, dev, func, PCI_BHLC_REG, &reg);
	if (err)
		return err;

	priv->header_type = PCI_HDRTYPE_TYPE(reg);
	if (priv->header_type != 0)
		return 0;

#if 1
	{
		struct pciio_acl acl;
		acl.domain = domain;
		acl.bus = bus;
		acl.device = dev;
		acl.function = func;

		err = ioctl(_state.pci_fd, PCI_IOC_RESERVE, &acl);
		if (err < 0)
			return err;
	}
#endif

	region = device->regions;
	for (bar = PCI_MAPREG_START; bar < PCI_MAPREG_END;
	     bar += sizeof(uint32_t), region++) {
		err = pci_read(domain, bus, dev, func, bar, &reg);
		if (err)
			return err;

		/* Probe the size of the region. */
		err = pci_write(domain, bus, dev, func, bar, (unsigned int)~0);
		if (err)
			return err;
		pci_read(domain, bus, dev, func, bar, &size);
		pci_write(domain, bus, dev, func, bar, reg);

		if (PCI_MAPREG_TYPE(reg) == PCI_MAPREG_TYPE_IO) {
			region->is_IO = 1;
			region->base_addr = PCI_MAPREG_IO_ADDR(reg);
			region->size = PCI_MAPREG_IO_SIZE(size);
		} else {
			if (PCI_MAPREG_MEM_PREFETCHABLE(reg))
				region->is_prefetchable = 1;
			switch(PCI_MAPREG_MEM_TYPE(reg)) {
			case PCI_MAPREG_MEM_TYPE_32BIT:
			case PCI_MAPREG_MEM_TYPE_32BIT_1M:
				region->base_addr = PCI_MAPREG_MEM_ADDR(reg);
				region->size = PCI_MAPREG_MEM_SIZE(size);
				break;
			case PCI_MAPREG_MEM_TYPE_64BIT:
				region->is_64 = 1;

				reg64 = reg;
				size64 = size;

				bar += sizeof(uint32_t);

				err = pci_read(domain, bus, dev, func, bar, &reg);
				if (err)
					return err;
				reg64 |= (uint64_t)reg << 32;

				err = pci_write(domain, bus, dev, func, bar,
				    (unsigned int)~0);
				if (err)
					return err;
				pci_read(domain, bus, dev, func, bar, &size);
				pci_write(domain, bus, dev, func, bar,
				    (unsigned int)(reg64 >> 32));
				size64 |= (uint64_t)size << 32;

				region->base_addr =
				    (unsigned long)PCI_MAPREG_MEM64_ADDR(reg64);
				region->size =
				    (unsigned long)PCI_MAPREG_MEM64_SIZE(size64);
				region++;
				break;
			}
		}
	}

	/* Probe expansion ROM if present */
	err = pci_read(domain, bus, dev, func, PCI_MAPREG_ROM, &reg);
	if (err)
		return err;
	if (reg != 0) {
		err = pci_write(domain, bus, dev, func, PCI_MAPREG_ROM,
		    (uint32_t)(~PCI_MAPREG_ROM_ENABLE));
		if (err)
			return err;
		pci_read(domain, bus, dev, func, PCI_MAPREG_ROM, &size);
		pci_write(domain, bus, dev, func, PCI_MAPREG_ROM, reg);
		if ((reg & PCI_MAPREG_MEM_ADDR_MASK) != 0) {
			priv->rom_base = reg & PCI_MAPREG_MEM_ADDR_MASK;
			device->rom_size = -(size & PCI_MAPREG_MEM_ADDR_MASK);
		}
	}

	return 0;
}

static int
pci_device_minix_read_rom(struct pci_device *dev, void *buffer)
{
    struct pci_device_private *priv = (struct pci_device_private *)(void *)dev;
    void *bios;
    pciaddr_t rom_base;
    size_t rom_size;
    uint32_t bios_val, command_val;
    int pci_rom;

    if (((priv->base.device_class >> 16) & 0xff) != PCI_CLASS_DISPLAY ||
	((priv->base.device_class >> 8) & 0xff) != PCI_SUBCLASS_DISPLAY_VGA)
	return ENOSYS;

    if (priv->rom_base == 0) {
#if defined(__amd64__) || defined(__i386__)
	/*
	 * We need a way to detect when this isn't the console and reject
	 * this request outright.
	 */
	rom_base = 0xc0000;
	rom_size = 0x10000;
	pci_rom = 0;
#else
	return ENOSYS;
#endif
    } else {
	rom_base = priv->rom_base;
	rom_size = dev->rom_size;
	pci_rom = 1;
#if 0
	if ((pcibus_conf_read(buses[dev->domain].fd, (unsigned int)dev->bus,
#else
	if ((pcibus_conf_read(_state.pci_fd, (unsigned int)dev->bus,
#endif
	    (unsigned int)dev->dev, (unsigned int)dev->func,
	    PCI_COMMAND_STATUS_REG, &command_val)) == -1)
	    return errno;
	if ((command_val & PCI_COMMAND_MEM_ENABLE) == 0) {
#if 0
	    if ((pcibus_conf_write(buses[dev->domain].fd,
#else
	    if ((pcibus_conf_write(_state.pci_fd,
#endif
	        (unsigned int)dev->bus, (unsigned int)dev->dev,
		(unsigned int)dev->func, PCI_COMMAND_STATUS_REG,
		command_val | PCI_COMMAND_MEM_ENABLE)) == -1)
		return errno;
	}
#if 0
	if ((pcibus_conf_read(buses[dev->domain].fd, (unsigned int)dev->bus,
#else
	if ((pcibus_conf_read(_state.pci_fd, (unsigned int)dev->bus,
#endif
	    (unsigned int)dev->dev, (unsigned int)dev->func,
	    PCI_MAPREG_ROM, &bios_val)) == -1)
	    return errno;
	if ((bios_val & PCI_MAPREG_ROM_ENABLE) == 0) {
#if 0
	    if ((pcibus_conf_write(buses[dev->domain].fd,
#else
	    if ((pcibus_conf_write(_state.pci_fd,
#endif
	        (unsigned int)dev->bus,
		(unsigned int)dev->dev, (unsigned int)dev->func,
		PCI_MAPREG_ROM, bios_val | PCI_MAPREG_ROM_ENABLE)) == -1)
		return errno;
	}
    }

    fprintf(stderr, "Using rom_base = 0x%lx 0x%lx (pci_rom=%d)\n",
        (long)rom_base, (long)rom_size, pci_rom);

#if 0
    bios = mmap(NULL, rom_size, PROT_READ, MAP_SHARED, buses[dev->domain].fd,
        (off_t)rom_base);

    if (bios == MAP_FAILED) {
	int serrno = errno;
	return serrno;
    }
#else
    {
	struct pciio_map map;
	int r;
	map.flags = 0;
	map.phys_offset = rom_base;
	map.size = rom_size;
	map.readonly = 1;

	r = ioctl(_state.pci_fd, PCI_IOC_MAP, &map);
	if (r < 0) {
		int serrno = errno;
		return serrno;
	}
	bios = map.vaddr_ret;
    }
#endif

    memcpy(buffer, bios, rom_size);

#if 0
    munmap(bios, rom_size);
#else
    {
	struct pciio_map map;
	int r;
	map.size = rom_size;
	map.vaddr = bios;

	r = ioctl(_state.pci_fd, PCI_IOC_UNMAP, &map);
	if (r < 0) {
		int serrno = errno;
		return serrno;
	}
    }
#endif

    if (pci_rom) {
	if ((command_val & PCI_COMMAND_MEM_ENABLE) == 0) {
#if 0
	    if ((pcibus_conf_write(buses[dev->domain].fd,
#else
	    if ((pcibus_conf_write(_state.pci_fd,
#endif
	        (unsigned int)dev->bus,
		(unsigned int)dev->dev, (unsigned int)dev->func,
		PCI_COMMAND_STATUS_REG, command_val)) == -1)
		return errno;
	}
	if ((bios_val & PCI_MAPREG_ROM_ENABLE) == 0) {
#if 0
	    if ((pcibus_conf_write(buses[dev->domain].fd,
#else
	    if ((pcibus_conf_write(_state.pci_fd,
#endif
	        (unsigned int)dev->bus,
		(unsigned int)dev->dev, (unsigned int)dev->func,
		PCI_MAPREG_ROM, bios_val)) == -1)
		return errno;
	}
    }

    return 0;
}

static const struct pci_system_methods minix_pci_methods = {
	.destroy = pci_system_minix_destroy,
	.destroy_device = pci_system_minix_destroy_device,
	.read_rom = pci_device_minix_read_rom,
	.probe = pci_device_minix_probe,
	.map_range = pci_device_minix_map_range,
	.unmap_range = pci_device_minix_unmap_range,
	.read = pci_device_minix_read,
	.write = pci_device_minix_write,
	.fill_capabilities = pci_fill_capabilities_generic,
	.boot_vga = pci_device_minix_boot_vga,
	.map_legacy = pci_device_minix_map_legacy,
	.unmap_legacy = pci_device_minix_unmap_legacy,
};

int
pci_system_minix_create(void)
{
	#define READ_BUFF_SIZE 4096
	#define DEV_PCI "/dev/pci"
	#define PROC_PCI "/proc/pci"

	FILE *file;
	struct pci_device_private *device;
	int ndevs;
	char buf[READ_BUFF_SIZE];
	
	/* Allocate top-level pci descriptor. */
	pci_sys = calloc(1, sizeof(struct pci_system));

	if (NULL == pci_sys) {
		return ENOMEM;
	}

	pci_sys->methods = &minix_pci_methods;

	file = fopen(PROC_PCI, "r");
	if (NULL == file) {
		return errno;
	}

	/* Allocate descriptors, one per pci device, so first figure how many
	 * there are to begin with. */
	ndevs = 0;
	while(NULL != fgets(buf, READ_BUFF_SIZE, file)) {
		ndevs++;
	}
		
	device = calloc(ndevs, sizeof(struct pci_device_private));
	if (device == NULL) {
		perror("PCI devices private structures failed");
		fclose(file);
		return ENOMEM;
	}
	pci_sys->devices = device;
	pci_sys->num_devices = ndevs;

	/* Go back to the start of the file, this time parse each line and
	 * store the pci information in the allocated device arrray. */
	if ( 0 != fseek(file, 0, SEEK_SET)) {
		fclose(file);
		return errno;
	}

	{
		// slot bcr/scr/pifr/rev vid:did:subvid:subdid dev_name
		// 0.0.30.0 6/4/1/a2 8086:244E:0000:0000 Intel 82801 PCI Bridge
		int domain, bus, dev, func;
		int bcr, scr, pifr, rev;
		int vid, did, svid, sdid;
		char dev_name[100];
		while(0 < fscanf(file, "%d.%d.%d.%d %x/%x/%x/%x %04X:%04X:%04X:%04X",
				&domain, &bus, &dev, &func,
				&bcr, &scr, &pifr, &rev,
				&vid, &did, &svid, &sdid
				)) {

			char *p = fgets(dev_name, 100, file);
#if 0
			fprintf(stderr, "%d.%d.%d.%d %x/%x/%x/%x %04X:%04X:%04X:%04X %s\n",
				domain, bus, dev, func,
				bcr, scr, pifr, rev,
				vid, did, dev_name
				);
#endif

			device->base.domain = domain;
			device->base.bus = bus;
			device->base.dev = dev;
			device->base.func = func;

			device->base.vendor_id = vid;
			device->base.device_id = did;
			device->base.subvendor_id = svid;
			device->base.subdevice_id = sdid;

			device->base.device_class = bcr << 16 | scr << 8 | pifr;
			device->base.revision = rev;

			device++;
		}
		fclose(file);
	}
		
	_state.pci_fd = open(DEV_PCI, O_RDONLY);
	if (_state.pci_fd < 0) {
		return errno;
	}

	return 0;
}
