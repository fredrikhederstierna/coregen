
GNU_TOOLCHAIN_NAME = arm-none-eabi-toolchain-gcc-12.2.0-binutils-2.39-newlib-4.2.0.20211231-softfloat
GNU_TOOLCHAIN_PATH = /opt/gcc/$(GNU_TOOLCHAIN_NAME)/bin

all:
	@# standard gnu11 needed to get ftruncate() definition
	gcc -o coregen -I. coregen.c riff_file_reader.c elfcore_file_writer.c -g3 -W -Wall -Wextra -Wno-unused-parameter -O2 -std=gnu11

run:
	./coregen app.gump app.elfcore

dis:
	$(GNU_TOOLCHAIN_PATH)/arm-none-eabi-objdump -SDax app.elfcore > app.elfcore.dis

read:
	$(GNU_TOOLCHAIN_PATH)/arm-none-eabi-readelf -a --headers --section-details --hex-dump=note0 app.elfcore | tee app.elfcore.info

debug:
	$(GNU_TOOLCHAIN_PATH)/arm-none-eabi-gdb app.elf app.elfcore

strip:
	cp app.elfcore app_stripped.elfcore
	$(GNU_TOOLCHAIN_PATH)/arm-none-eabi-strip -s app_stripped.elfcore
#	$(GNU_TOOLCHAIN_PATH)/arm-none-eabi-strip --remove-section=.shstrtab app_stripped.elfcore

clean:
	rm -f *.o coregen
