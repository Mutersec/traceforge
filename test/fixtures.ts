/** Synthetic minimal ELF64 with section names and a tiny .text section. */
export const elfFixture = (): Buffer => {
  const buffer = Buffer.alloc(0x200);
  buffer[0] = 0x7f;
  buffer[1] = 0x45;
  buffer[2] = 0x4c;
  buffer[3] = 0x46;
  buffer[4] = 2;
  buffer[5] = 1;
  buffer[6] = 1;
  buffer.writeUInt16LE(2, 16);
  buffer.writeUInt16LE(0x3e, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x401000n, 24);
  buffer.writeBigUInt64LE(0x40n, 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(0, 54);
  buffer.writeUInt16LE(0, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(4, 60);
  buffer.writeUInt16LE(1, 62);
  const section = (
    index: number,
    name: number,
    type: number,
    flags: bigint,
    address: bigint,
    offset: number,
    size: number,
    link = 0,
    entrySize = 0,
  ): void => {
    const base = 0x40 + index * 64;
    buffer.writeUInt32LE(name, base);
    buffer.writeUInt32LE(type, base + 4);
    buffer.writeBigUInt64LE(flags, base + 8);
    buffer.writeBigUInt64LE(address, base + 16);
    buffer.writeBigUInt64LE(BigInt(offset), base + 24);
    buffer.writeBigUInt64LE(BigInt(size), base + 32);
    buffer.writeUInt32LE(link, base + 40);
    buffer.writeUInt32LE(0, base + 44);
    buffer.writeBigUInt64LE(1n, base + 48);
    buffer.writeBigUInt64LE(BigInt(entrySize), base + 56);
  };
  const names = "\0.shstrtab\0.text\0";
  buffer.write(names, 0x140, "utf8");
  section(1, 1, 3, 0n, 0n, 0x140, names.length);
  section(2, 11, 1, 6n, 0x401000n, 0x160, 4);
  buffer.write("ret\0", 0x160, "utf8");
  return buffer;
};

/** Synthetic minimal PE32+ with one imported symbol. */
export const peFixture = (): Buffer => {
  const buffer = Buffer.alloc(0x400);
  buffer.write("MZ", 0, "ascii");
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.write("PE\0\0", 0x80, "ascii");
  const coff = 0x84;
  buffer.writeUInt16LE(0x8664, coff);
  buffer.writeUInt16LE(1, coff + 2);
  buffer.writeUInt32LE(0x12345678, coff + 4);
  buffer.writeUInt16LE(240, coff + 16);
  buffer.writeUInt16LE(0x22, coff + 18);
  const optional = coff + 20;
  buffer.writeUInt16LE(0x20b, optional);
  buffer.writeUInt32LE(0x1000, optional + 16);
  buffer.writeBigUInt64LE(0x140000000n, optional + 24);
  buffer.writeUInt32LE(16, optional + 108);
  const directories = optional + 112;
  buffer.writeUInt32LE(0x1000, directories + 8);
  buffer.writeUInt32LE(0x28, directories + 12);
  const sectionTable = optional + 240;
  buffer.write(".rdata\0\0", sectionTable, "ascii");
  buffer.writeUInt32LE(0x200, sectionTable + 8);
  buffer.writeUInt32LE(0x1000, sectionTable + 12);
  buffer.writeUInt32LE(0x200, sectionTable + 16);
  buffer.writeUInt32LE(0x200, sectionTable + 20);
  buffer.writeUInt32LE(0x40000040, sectionTable + 36);
  buffer.writeUInt32LE(0x1060, 0x200);
  buffer.writeUInt32LE(0x1040, 0x20c);
  buffer.writeUInt32LE(0x1060, 0x210);
  buffer.write("KERNEL32.dll\0", 0x240, "ascii");
  buffer.writeBigUInt64LE(0x1080n, 0x260);
  buffer.writeUInt16LE(0, 0x280);
  buffer.write("CreateFileA\0", 0x282, "ascii");
  return buffer;
};

export const wasmFixture = (): Buffer => {
  const payload = Buffer.from([4, 0x6d, 0x65, 0x74, 0x61, 0x78]);
  const buffer = Buffer.alloc(8 + 2 + payload.length);
  buffer.write("\0asm", 0, "binary");
  buffer.writeUInt32LE(1, 4);
  buffer[8] = 0;
  buffer[9] = payload.length;
  payload.copy(buffer, 10);
  return buffer;
};
