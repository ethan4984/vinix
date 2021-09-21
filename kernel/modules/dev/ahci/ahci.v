module ahci

import pci
import memory
import lib
import stat
import klock
import event
import event.eventstruct
import resource
import errno
import block.partition
import fs

const (
	ahci_class = 0x1
	ahci_subclass = 0x6
	ahci_progif = 0x1
)

[packed]
struct AHCIRegisters {
pub mut:
	cap u32
	ghc u32
	ints u32
	pi u32
	vs u32
	ccc_ctl u32
	ccc_ports u32
	em_lock u32
	em_ctl u32
	cap2 u32
	bohc u32
	reserved[29] u32
	vendor[24] u32
}

[packed]
struct AHCIPortRegisters {
pub mut:
	clb u32
	clbu u32
	fb u32
	fbu u32
	ints u32
	ie u32
	cmd u32
	reserved0 u32
	tfd u32
	sig u32
	ssts u32
	sstl u32
	serr u32
	sact u32
	ci u32
	sntf u32
	fbs u32
	devslp u32
	reserved1[11] u32
	vs[10] u32
}

struct AHCIController {
pub mut:
	pci_bar pci.PCIBar

	regs &AHCIRegisters
}

__global (
	ahci_controller_list []&AHCIController
)

pub fn (mut c AHCIController) initialise(pci_device &pci.PCIDevice) int {
	pci_device.enable_bus_mastering()

	if pci_device.is_bar_present(0x5) == false {
		print('ahci: unable to locate BAR5\n')
		return -1
	}

	c.pci_bar = pci_device.get_bar(0x5)

	return 0
}

pub fn initialise() {
	for device in scanned_devices {
		if device.class == ahci_class && device.subclass == ahci_subclass && device.prog_if == ahci_progif {
			mut ahci_device := &AHCIController { regs: 0 }

			if ahci_device.initialise(device) != -1 {
				ahci_controller_list << ahci_device
			}
		}
	}
}
