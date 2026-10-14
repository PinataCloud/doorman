// Package vscode-extension/ as build/vscode/doorman.vsix, which
// electron-builder ships as Resources/vscode/ and main/vscode-ext-install.ts
// hands to the editor's own CLI (`code --install-extension <path> --force`).
//
// WHY BY HAND. A .vsix is a plain ZIP with two extra members — an OPC content
// types part and a `extension.vsixmanifest` — and `vsce`, the official
// packager, is a 40 MB dependency tree whose only job here would be to write
// those two files and zip seven more. Verified end to end against the shipped
// VS Code 1.136.2: an archive built exactly like this installs (`--install-
// extension` → exit 0, listed by `--list-extensions --show-versions`) and
// uninstalls cleanly. So the extension has no build step of its own and
// nothing to keep in sync: the JS that ships is the JS in the repo.
//
// The ZIP writer below writes STORED entries with a fixed DOS timestamp, so a
// rebuild of unchanged sources is byte-identical. It lives here because this
// script runs before — and independently of — any TypeScript build, and
// nothing at runtime needs it: scripts/ is not part of the packaged app.
import { mkdirSync, readFileSync, writeFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const source = join(root, "vscode-extension");
const outDir = join(root, "build", "vscode");
const outFile = join(outDir, "doorman.vsix");

// ---- minimal ZIP (STORED) -------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(data) {
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

function buildZip(entries) {
  const chunks = [];
  const central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBytes = Buffer.from(name, "utf8");
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(0, 8); // method: stored
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    chunks.push(local, nameBytes, data);

    const entry = Buffer.alloc(46);
    entry.writeUInt32LE(0x02014b50, 0);
    entry.writeUInt16LE(20, 4); // version made by
    entry.writeUInt16LE(20, 6); // version needed
    entry.writeUInt16LE(0, 8);
    entry.writeUInt16LE(0, 10);
    entry.writeUInt16LE(DOS_TIME, 12);
    entry.writeUInt16LE(DOS_DATE, 14);
    entry.writeUInt32LE(crc, 16);
    entry.writeUInt32LE(data.length, 20);
    entry.writeUInt32LE(data.length, 24);
    entry.writeUInt16LE(nameBytes.length, 28);
    entry.writeUInt16LE(0, 30); // extra
    entry.writeUInt16LE(0, 32); // comment
    entry.writeUInt16LE(0, 34); // disk
    entry.writeUInt16LE(0, 36); // internal attrs
    entry.writeUInt32LE(0, 38); // external attrs
    entry.writeUInt32LE(offset, 42);
    central.push(entry, nameBytes);

    offset += local.length + nameBytes.length + data.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...chunks, centralBuf, end]);
}

// ---- the two OPC parts a .vsix needs beyond the files ---------------------

function contentTypes() {
  return `<?xml version="1.0" encoding="utf-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="json" ContentType="application/json"/>
  <Default Extension="js" ContentType="application/javascript"/>
  <Default Extension="md" ContentType="text/markdown"/>
  <Default Extension="png" ContentType="image/png"/>
  <Default Extension="woff" ContentType="font/woff"/>
  <Default Extension="vsixmanifest" ContentType="text/xml"/>
</Types>
`;
}

/** XML text escaping — the description is prose from package.json. */
function xml(text) {
  return String(text).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function manifest(pkg) {
  return `<?xml version="1.0" encoding="utf-8"?>
<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011">
  <Metadata>
    <Identity Language="en-US" Id="${xml(pkg.name)}" Version="${xml(pkg.version)}" Publisher="${xml(pkg.publisher)}"/>
    <DisplayName>${xml(pkg.displayName)}</DisplayName>
    <Description xml:space="preserve">${xml(pkg.description)}</Description>
    <Tags>doorman,agent,security,spend</Tags>
    <Categories>Other</Categories>
    <GalleryFlags>Public</GalleryFlags>
    <Icon>extension/icon.png</Icon>
  </Metadata>
  <Installation>
    <InstallationTarget Id="Microsoft.VisualStudio.Code" Version="[1.90,)"/>
  </Installation>
  <Dependencies/>
  <Assets>
    <Asset Type="Microsoft.VisualStudio.Code.Manifest" Path="extension/package.json" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Content.Details" Path="extension/README.md" Addressable="true"/>
    <Asset Type="Microsoft.VisualStudio.Services.Icons.Default" Path="extension/icon.png" Addressable="true"/>
  </Assets>
</PackageManifest>
`;
}

// ---- build ----------------------------------------------------------------

// The extension's version IS the app's version. One number for the pair means
// "is the editor's copy current?" is a string comparison the doctor can make
// (lib/vscode-ext.ts needsInstall) rather than a compatibility matrix.
const appVersion = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;
const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8"));
pkg.version = appVersion;

const readme = readFileSync(join(source, "README.md"), "utf8");
// The product's own mark, the same file the app renders (scripts/make-brand.py)
// — never a second copy to drift. 512 px with alpha; VS Code scales it for the
// Extensions view, which wants ≥128 px.
const icon = readFileSync(join(root, "assets", "doorman-mark-512.png"));
const entries = [
  { name: "[Content_Types].xml", data: Buffer.from(contentTypes(), "utf8") },
  { name: "extension.vsixmanifest", data: Buffer.from(manifest(pkg), "utf8") },
  { name: "extension/package.json", data: Buffer.from(`${JSON.stringify(pkg, null, 2)}\n`, "utf8") },
  { name: "extension/extension.js", data: readFileSync(join(source, "extension.js")) },
  { name: "extension/README.md", data: Buffer.from(readme, "utf8") },
  { name: "extension/icon.png", data: icon },
  // The one-glyph icon font behind `$(doorman-mark)` in the status bar —
  // generated by scripts/make-brand.py and committed.
  { name: "extension/doorman-icons.woff", data: readFileSync(join(source, "doorman-icons.woff")) },
];

mkdirSync(outDir, { recursive: true });
writeFileSync(outFile, buildZip(entries));
console.log(`packaged ${pkg.publisher}.${pkg.name}@${pkg.version} → build/vscode/doorman.vsix (${statSync(outFile).size} bytes)`);
