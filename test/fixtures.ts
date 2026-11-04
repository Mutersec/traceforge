/** Synthetic ELF64: PIE executable with program headers, a producer string and a .text section. */
export const elfFixture = (): Buffer => {
  const buffer = Buffer.alloc(0x300);
  buffer[0] = 0x7f;
  buffer[1] = 0x45;
  buffer[2] = 0x4c;
  buffer[3] = 0x46;
  buffer[4] = 2;
  buffer[5] = 1;
  buffer[6] = 1;
  buffer[7] = 3;
  buffer[8] = 1;
  buffer.writeUInt16LE(3, 16);
  buffer.writeUInt16LE(0x3e, 18);
  buffer.writeUInt32LE(1, 20);
  buffer.writeBigUInt64LE(0x401000n, 24);
  buffer.writeBigUInt64LE(0x1c0n, 32);
  buffer.writeBigUInt64LE(0x40n, 40);
  buffer.writeUInt16LE(64, 52);
  buffer.writeUInt16LE(56, 54);
  buffer.writeUInt16LE(4, 56);
  buffer.writeUInt16LE(64, 58);
  buffer.writeUInt16LE(4, 60);
  buffer.writeUInt16LE(1, 62);
  const program = (
    index: number,
    type: number,
    flags: number,
    offset: number,
    size: number,
  ): void => {
    const base = 0x1c0 + index * 56;
    buffer.writeUInt32LE(type, base);
    buffer.writeUInt32LE(flags, base + 4);
    buffer.writeBigUInt64LE(BigInt(offset), base + 8);
    buffer.writeBigUInt64LE(BigInt(size), base + 32);
    buffer.writeBigUInt64LE(BigInt(size), base + 40);
  };
  program(0, 0x6474e551, 6, 0, 0);
  program(1, 0x6474e552, 4, 0x160, 4);
  program(2, 3, 4, 0x2c0, 27);
  program(3, 1, 5, 0, 0x180);
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
  const names = "\0.shstrtab\0.text\0.comment\0";
  buffer.write(names, 0x140, "utf8");
  buffer.write("GCC: (GNU) 13.2.1\0", 0x2a0, "utf8");
  buffer.write("/lib64/ld-linux-x86-64.so.2\0", 0x2c0, "utf8");
  section(1, 1, 3, 0n, 0n, 0x140, names.length);
  section(2, 11, 1, 6n, 0x401000n, 0x160, 4);
  section(3, 17, 1, 2n, 0n, 0x2a0, 18);
  buffer.write("ret\0", 0x160, "utf8");
  return buffer;
};

/** Synthetic PE32+ with one imported symbol and DYNAMIC_BASE, NX and high-entropy VA set. */
export const peFixture = (dllCharacteristics = 0x0160): Buffer => {
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
  buffer[optional + 2] = 14;
  buffer[optional + 3] = 29;
  buffer.writeUInt32LE(0x1000, optional + 16);
  buffer.writeBigUInt64LE(0x140000000n, optional + 24);
  buffer.writeUInt16LE(6, optional + 40);
  buffer.writeUInt16LE(0, optional + 42);
  buffer.writeUInt32LE(0x4000, optional + 56);
  buffer.writeUInt16LE(3, optional + 68);
  buffer.writeUInt16LE(dllCharacteristics, optional + 70);
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

/** Synthetic thin Mach-O executable with MH_PIC, a read-only segment and LC_BUILD_VERSION. */
export const machoFixture = (
  options: { readonly headerFlags?: number; readonly maxProt?: number } = {},
): Buffer => {
  const headerFlags = options.headerFlags ?? 0x201;
  const maxProt = options.maxProt ?? 5;
  const buffer = Buffer.alloc(136);
  buffer.writeUInt32LE(0xfeedfacf, 0);
  buffer.writeInt32LE(0x0100000c, 4);
  buffer.writeInt32LE(0, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(2, 16);
  buffer.writeUInt32LE(104, 20);
  buffer.writeUInt32LE(headerFlags, 24);
  const segment = 32;
  buffer.writeUInt32LE(0x19, segment);
  buffer.writeUInt32LE(72, segment + 4);
  buffer.write("__TEXT", segment + 8, "ascii");
  buffer.writeBigUInt64LE(0x1000n, segment + 24);
  buffer.writeBigUInt64LE(0x1000n, segment + 32);
  buffer.writeUInt32LE(0x1000, segment + 40);
  buffer.writeUInt32LE(0x1000, segment + 48);
  buffer.writeUInt32LE(maxProt, segment + 56);
  buffer.writeUInt32LE(maxProt & 0x7, segment + 60);
  buffer.writeUInt32LE(0, segment + 64);
  const build = 104;
  buffer.writeUInt32LE(0x32, build);
  buffer.writeUInt32LE(32, build + 4);
  buffer.writeUInt32LE(1, build + 8);
  buffer.writeUInt32LE((13 << 16) | (2 << 8) | 1, build + 12);
  buffer.writeUInt32LE(14 << 16, build + 16);
  buffer.writeUInt32LE(1, build + 20);
  buffer.writeUInt32LE(1, build + 24);
  buffer.writeUInt32LE(902 << 16, build + 28);
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
}

/** XML property list with the claims a macOS bundle manifest normally declares. */
export const xmlPlistFixture = (
  overrides: Readonly<Record<string, string>> = {},
): Buffer => {
  const entries: readonly (readonly [string, string])[] = [
    ["CFBundleIdentifier", overrides.CFBundleIdentifier ?? "com.acme.example"],
    ["CFBundleName", overrides.CFBundleName ?? "Example"],
    ["CFBundleExecutable", overrides.CFBundleExecutable ?? "example"],
    ["CFBundleShortVersionString", overrides.CFBundleShortVersionString ?? "1.4.2"],
    ["CFBundleVersion", overrides.CFBundleVersion ?? "1420"],
    ["LSMinimumSystemVersion", "12.0"],
    ["CFBundlePackageType", "APPL"],
    ["NSHumanReadableCopyright", "Copyright © Acme & Co"],
    ["CFBundleSupportedPlatforms", "MacOSX"],
  ];
  const body = entries
    .map(
      ([key, value]) =>
        `\t\t<key>${key}</key>\n\t\t<string>${value
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")}</string>`,
    )
    .join("\n");
  return Buffer.from(
    `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
${body}
	</dict>
</plist>
`,
    "utf8",
  );
};

/**
 * Binary property list (`bplist00`) written byte by byte: object headers, an
 * extended length marker, a UTF-16 string, an integer, a boolean and a four-byte
 * offset table are all explicit, so the reader cannot pass by sharing a
 * misunderstanding with a generator.
 */
export const binaryPlistFixture = (): Buffer => {
  const withLength = (nibble: number, length: number, payload: Buffer): Buffer =>
    length < 15
      ? Buffer.concat([Buffer.from([nibble | length]), payload])
      : Buffer.concat([Buffer.from([nibble | 0x0f, 0x10, length]), payload]);
  const ascii = (value: string): Buffer =>
    withLength(0x50, value.length, Buffer.from(value, "ascii"));
  const utf16 = (value: string): Buffer => {
    const bytes = Buffer.alloc(value.length * 2);
    for (let index = 0; index < value.length; index += 1)
      bytes.writeUInt16BE(value.charCodeAt(index), index * 2);
    return withLength(0x60, value.length, bytes);
  };
  const objects: Buffer[] = [
    // 0: dict of three pairs: keys 1, 3, 7 -> values 2, 4, 8, refs interleaved
    // as Apple writes them: all key refs first, then all value refs.
    withLength(0xc0, 3, Buffer.from([1, 3, 7, 2, 4, 8])),
    ascii("CFBundleIdentifier"),
    ascii("com.acme.helper"),
    ascii("CFBundleName"),
    utf16("Helper"),
    Buffer.from([0x09]),
    Buffer.from([0x11, 0x00, 0x2a]),
    ascii("LSUIElement"),
    Buffer.from([0x08]),
  ];
  const magic = Buffer.from("bplist00", "ascii");
  const offsets: number[] = [];
  let position = magic.length;
  for (const object of objects) {
    offsets.push(position);
    position += object.length;
  }
  const body = Buffer.concat(objects);
  const table = Buffer.alloc(offsets.length * 4);
  offsets.forEach((offset, index) => table.writeUInt32BE(offset, index * 4));
  const trailer = Buffer.alloc(32);
  trailer[6] = 4;
  trailer[7] = 1;
  trailer.writeBigUInt64BE(BigInt(offsets.length), 8);
  trailer.writeBigUInt64BE(0n, 16);
  trailer.writeBigUInt64BE(BigInt(position), 24);
  return Buffer.concat([magic, body, table, trailer]);
};
