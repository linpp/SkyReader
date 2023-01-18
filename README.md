SkyReader
=========

A Skylander portal reader/editor/writer for OSX.  

May compile on other platforms due to use of the cross platform hidapi usb library.   Please check out the forks for other platform builds.

HIDAPI can be found here http://www.signal11.us/oss/hidapi/

    Usage:
    editor [-i <file>|-p] [-s <skylander>] [-d] [-e] [-o <file>|-P] [-M <money>] [-X experience] ... 

    Reading/Writing:
    -i <file>  read skylander data from file, with option to decrypt the data.
    -p		read skylander data from portal and decrypt the data.
    -s <skylander> select which skylander.
    -d		decrypt the data read from the file.
    -o <file>	write skylander data to <filename>.
    -P		encrypt and write skylander data to the portal.
    -e		encrypt data when writing file.
    -D		dump the data of a skylander to the display.
    -l		List skylanders on portal.
    -r <device> redirect portal [pP] options to RC522 on serial device.

    Upgrade:
    -M <money>	upgrade skylander money (max 65,000).
    -X <xp>		upgrade skylander Experience (level 10 = 33,000).
    -H <hp>		upgrade skylander Hero Points (max 100).
    -C <challenges>	upgrade skylander challenges.
    -L <points>	upgrade the skylander skillpoints on the left path.
    -R <points>	upgrade the skylander skillpoints on the right path.
    -c		update checksums.

It is mandatory that you specify an input and an output.  So input either from a file with the `-i` option or the Portal with the `-p` option. An output must also be specified either from a file with the `-o` option or to the Portal with the `-P` option.  However the input and output cannot both be the Portal. 

Examples
--------
        editor -p -o spyro.bin
This would save a copy of the figurine to the file spyro.bin

        editor -i spyro.bin -o spyro_upgrade.bin -L 65535 -M 65000 -X 33000 -H 100
upgrade spyro.bin using skills on the LEFT path seen in the character menu
and write it to file spyro_upgrade.bin

    editor -i spyro.bin -P -M 65000 -X 33000
Upgrade skylander, leave skills as is, and write to the portal.

    editor -i spyro.bin -P
Read file from spyro.bin and write it to the portal.

    editor -r /dev/cu.usbserial-14430 -p -D
Redirect portal (-p) to an mfrc522 arduino on /dev/cu.usbserial-14430 and dump the card on the device.

    editor -r /dev/cu.usbserial-14430 -i spyro.bin -P
Redirect portal (-P) to an mfrc522 arduino on /dev/cu.usbserial-14430 and write spyro.bin to the card on the device.
