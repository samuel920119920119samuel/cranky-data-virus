data_virus.o : data_virus.asm
	nasm -f elf -F dwarf -g data_virus.asm
data_virus : data_virus.o
	ld -m elf_i386 -e v_start -o data_virus data_virus.o
hello.o : hello.asm
	nasm -f elf -F dwarf -g hello.asm
hello : hello.o
	ld -m elf_i386 -e _start -o hello hello.o
all: data_virus.o hello.o
	ld -m elf_i386 -o _start -o hello hello.o
	ld -m elf_i386 -e v_start -o data_virus data_virus.o
