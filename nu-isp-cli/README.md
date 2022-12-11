# nu-isp-cli

Command line implementation of [nu-isp flashing protocol over hid](https://github.com/OpenNuvoton/Nuvoton_Tools/blob/master/doc/NuMicro_ISP_Flow_And_Command_Set.pdf) used by Nuvoton microcontrollers.

## setup

### windows

No special preparaiton needed. Install it, and it just works.

### mac

No special preparaiton needed. Install it, and it just works.

### linux

You'll need libusb. Depending on your distribution, you might need to `sudo apt-get install libusb-1.0-0-dev pkg-config`.

If you'd like not to use sudo everytime, you'll need udev rules. With your board plugged in and in bootloader mode, use `lsusb` to find its vendor-id and product-id, seen here as 0416:a316.

```bash
$ lsusb
...
Bus 001 Device 002: ID 0416:a316 Winbond Electronics Corp.
...
```

Then put them in the following format and save it to something like /etc/udev/rules.d/99-nuvoton-isp.rules

```bash
SUBSYSTEM=="usb", ATTR{idVendor}=="0416", ATTR{idProduct}=="3f00", MODE="666"
SUBSYSTEM=="usb", ATTR{idVendor}=="0416", ATTR{idProduct}=="a316", MODE="666"
```

Then replug your board and let it into bootloader mode again.

## install

`cargo install nu-isp-cli`

## use

```bash
$ nu-isp-cli
Nuvoton NuMicro ISP_HID Programming Tool [unofficial]
Version 0.7.2

Quick Reference:

    nu-isp-cli <INPUT>

    nu-isp-cli info

    nu-isp-cli erase

    nu-isp-cli flash <INPUT>

    nu-isp-cli <VID:PID> info

    nu-isp-cli <VID:PID> erase

    nu-isp-cli <VID:PID> flash <INPUT>

    nu-isp-cli --help
```

It will attempt to autodetect a device from list of known device-ids and using the first one available or you can specify vid and pid (before the subcommand) instead.

```bash
$ nu-isp-cli info
Printing info...
DEVICE NUC126LG4AE (PDID: 00C05204)
CONFIG FFFFFF7E:0001C000
Done.
```

It accepts binary files, elf files or ihex format text files for your convenience.

```bash
$ nu-isp-cli firmware.elf
```

## supported chips

It is tested with NUC123 , NUC126 , NUC029, M252, M253 and M032 series. and it should work with many other chips as long as their bootloaders are compatible.
I'll happily add new chips to the list upon your report confirming its correct operation.
