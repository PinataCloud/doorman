import { describe, expect, it } from "vitest";
import { guardSelfWrite } from "../main/guard/decision.js";

/**
 * The guard's self-protection (decision.ts guardSelfWrite) with Windows path
 * rules, on any OS: the platform and environment are injected. Every case in
 * the first block was ALLOWED on Windows 11 before the fix — the canonical
 * path came back `\`-separated while the check looked for `${dir}/`.
 */
const HOME = "C:\\Users\\wdev";
const ENV = {
  APPDATA: "C:\\Users\\wdev\\AppData\\Roaming",
  LOCALAPPDATA: "C:\\Users\\wdev\\AppData\\Local",
  USERPROFILE: "C:\\Users\\wdev",
  USERNAME: "wdev",
  HOMEDRIVE: "C:",
  HOMEPATH: "\\Users\\wdev",
};
const WIN = { platform: "win32", env: ENV } as const;
const G = "C:\\Users\\wdev\\AppData\\Roaming\\Doorman\\doorman\\guard";
const GF = G.replace(/\\/g, "/");
const CWD = "C:\\repo";

const shell = (command: string, cwd = CWD) => guardSelfWrite("Bash", { command }, cwd, [G], HOME, WIN);
const write = (file_path: string, tool = "Write") => guardSelfWrite(tool, { file_path, content: "{}" }, CWD, [G], HOME, WIN);

describe("guardSelfWrite on Windows — the reported misses", () => {
  it("holds Write/Edit into the guard directory, any separator or case", () => {
    expect(write(`${G}\\policy.json`)).toBeDefined();
    expect(write(`${GF}/policy.json`)).toBeDefined();
    expect(write(`${G}\\policy.json`.toLowerCase(), "Edit")).toBeDefined();
    expect(write(`${G}\\pending\\a.reply.json`)).toBeDefined();
  });

  it("holds shell redirects into it: backslash, forward slash, Git Bash /c/", () => {
    expect(shell(`echo {} > "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`echo {} > "${GF}/policy.json"`)).toBeDefined();
    expect(shell(`echo {} > /c/Users/wdev/AppData/Roaming/Doorman/doorman/guard/policy.json`)).toBeDefined();
    expect(shell(`echo {} > "${G}\\pending\\a.reply.json"`)).toBeDefined();
  });

  it("holds PowerShell and cmd writes, including through %APPDATA% and $env:APPDATA", () => {
    expect(shell(`powershell -Command "Set-Content -Path '${G}\\policy.json' -Value '{}'"`)).toBeDefined();
    expect(shell(`cmd /c "echo {} > %APPDATA%\\Doorman\\doorman\\guard\\policy.json"`)).toBeDefined();
    expect(shell(`Set-Content "$env:APPDATA\\Doorman\\doorman\\guard\\policy.json" '{}'`)).toBeDefined();
  });

  it("matches the runtime call's shape without an injected platform (drive-letter guard dir)", () => {
    expect(guardSelfWrite("Write", { file_path: `${G}\\policy.json` }, CWD, [G], HOME)).toBeDefined();
    expect(guardSelfWrite("Bash", { command: `echo {} > "${G}\\policy.json"` }, CWD, [G], HOME)).toBeDefined();
    expect(guardSelfWrite("Read", { file_path: `${G}\\policy.json` }, CWD, [G], HOME)).toBeUndefined();
  });
});

describe("guardSelfWrite on Windows — what already held still holds", () => {
  it("holds deleting the directory", () => {
    expect(shell(`rm -rf "${GF}"`)).toBeDefined();
    expect(shell(`Remove-Item -Recurse -Force '${G}'`)).toBeDefined();
  });
});

describe("guardSelfWrite on Windows — every writer", () => {
  it("holds the PowerShell content and item cmdlets", () => {
    expect(shell(`'{}' | Out-File -FilePath "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`Add-Content -Path "${G}\\policy.json" -Value 'x'`)).toBeDefined();
    expect(shell(`New-Item -ItemType File -Path "${G}\\pending\\a.reply.json" -Force`)).toBeDefined();
    expect(shell(`New-Item -ItemType File "${G}\\pending\\a.reply.json"`)).toBeDefined();
    expect(shell(`Copy-Item x '${G}\\policy.json'`)).toBeDefined();
    expect(shell(`Copy-Item -Destination '${G}\\policy.json' -Path C:\\tmp\\x.json`)).toBeDefined();
    expect(shell(`cp -Destination '${G}\\policy.json' C:\\tmp\\x.json`)).toBeDefined();
    expect(shell(`Move-Item C:\\tmp\\x.json "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`Set-Content -Path:${G}\\policy.json -Value '{}'`)).toBeDefined();
  });

  it("holds cmd and the copy tools", () => {
    expect(shell(`cmd /c copy C:\\tmp\\x.json "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`C:\\Windows\\System32\\cmd.exe /c "copy C:\\tmp\\x.json ${G}\\policy.json"`)).toBeDefined();
    expect(shell(`echo {} | tee "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`'{}' | Tee-Object -FilePath "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`xcopy C:\\tmp\\policy.json "${G}\\" /Y`)).toBeDefined();
    expect(shell(`robocopy C:\\tmp "${G}" policy.json`)).toBeDefined();
    expect(shell(`robocopy C:\\tmp C:\\out /LOG:${G}\\policy.json`)).toBeDefined();
  });

  it("holds a relative write after cd / Set-Location into the directory", () => {
    expect(shell(`cd "${G}"; Set-Content policy.json '{}'`)).toBeDefined();
    expect(shell(`Set-Location -Path '${G}'; '{}' > policy.json`)).toBeDefined();
    expect(shell(`cd /d ${G} && echo {} > pending\\a.reply.json`)).toBeDefined();
    expect(shell(`cd $env:APPDATA\\Doorman\\doorman; Set-Content guard\\policy.json '{}'`)).toBeDefined();
    expect(shell(`cd /c/Users/wdev/AppData/Roaming/Doorman/doorman/guard && echo {} > policy.json`)).toBeDefined();
    expect(shell(`Set-Content policy.json '{}'`, G)).toBeDefined();
  });

  it("holds a quoted guard path fed to powershell -Command, cmd /c and bash -c", () => {
    expect(shell(`powershell.exe -NoProfile -Command "Remove-Item '${G}\\pending\\x.json'"`)).toBeDefined();
    expect(shell(`pwsh -c "'{}' | Set-Content '${GF}/policy.json'"`)).toBeDefined();
    expect(shell(`cmd.exe /c "type nul > \\"${G}\\policy.json\\""`)).toBeDefined();
    expect(shell(`bash -c "echo {} > '${G}\\policy.json'"`)).toBeDefined();
    expect(shell(`bash -c 'echo {} > /c/Users/wdev/AppData/Roaming/Doorman/doorman/guard/policy.json'`)).toBeDefined();
  });

  it("holds mixed separators and either drive-letter case", () => {
    expect(write("C:/Users\\wdev/AppData\\Roaming/Doorman\\doorman/guard\\policy.json")).toBeDefined();
    expect(write(`c:${G.slice(2)}\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > c:\\users\\WDEV\\appdata\\roaming\\doorman\\DOORMAN\\guard\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > C:\\Users\\wdev\\AppData\\Roaming\\Doorman\\doorman\\guard\\.\\x\\..\\policy.json`)).toBeDefined();
  });
});

describe("guardSelfWrite on Windows — other spellings of the same directory", () => {
  it("holds every environment-variable spelling", () => {
    expect(shell(`echo {} > %APPDATA%\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > %appdata%\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > %USERPROFILE%\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > %HOMEDRIVE%%HOMEPATH%\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > C:\\Users\\%USERNAME%\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > %APPDATA:~0%\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell(`Set-Content "\${env:APPDATA}\\Doorman\\doorman\\guard\\policy.json" '{}'`)).toBeDefined();
    expect(shell(`Set-Content "$($env:APPDATA)\\Doorman\\doorman\\guard\\policy.json" '{}'`)).toBeDefined();
    expect(shell(`Set-Content "$env:USERPROFILE\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json" '{}'`)).toBeDefined();
    expect(shell(`Set-Content ~\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json '{}'`)).toBeDefined();
    expect(shell(`Set-Content "$HOME\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json" '{}'`)).toBeDefined();
    expect(shell(`echo {} > "$APPDATA/Doorman/doorman/guard/policy.json"`)).toBeDefined();
  });

  it("falls back to the profile for %APPDATA% when the environment lacks it", () => {
    const bare = guardSelfWrite("Bash", { command: `echo {} > %APPDATA%\\Doorman\\doorman\\guard\\policy.json` }, CWD, [G], HOME, {
      platform: "win32",
      env: {},
    });
    expect(bare).toBeDefined();
  });

  it("holds the drive-less, mount, device and admin-share forms", () => {
    expect(shell(`echo {} > \\Users\\wdev\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell(`echo {} > /mnt/c/Users/wdev/AppData/Roaming/Doorman/doorman/guard/policy.json`)).toBeDefined();
    expect(shell(`echo {} > /cygdrive/c/Users/wdev/AppData/Roaming/Doorman/doorman/guard/policy.json`)).toBeDefined();
    expect(write(`\\\\?\\${G}\\policy.json`)).toBeDefined();
    expect(write(`\\\\.\\${G}\\policy.json`)).toBeDefined();
    expect(write(`\\\\localhost\\c$\\Users\\wdev\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(write("C:policy.json")).toBeUndefined();
    expect(guardSelfWrite("Write", { file_path: "C:policy.json" }, G, [G], HOME, WIN)).toBeDefined();
  });

  it("holds what Win32 path normalization folds: trailing dots and spaces, data streams", () => {
    expect(write(`${G}.\\policy.json`)).toBeDefined();
    expect(write(`${G}\\policy.json.`)).toBeDefined();
    expect(shell(`Remove-Item -Recurse "${G}. "`)).toBeDefined();
    expect(write(`${G}::$INDEX_ALLOCATION\\policy.json`)).toBeDefined();
    expect(write(`${G}\\policy.json::$DATA`)).toBeDefined();
    expect(write(`${G}:hidden`)).toBeDefined();
  });

  it("holds wildcards PowerShell and cmd expand", () => {
    expect(shell(`Remove-Item C:\\Users\\wdev\\AppData\\Roaming\\Doorman\\doorman\\gu*\\policy.json`)).toBeDefined();
    expect(shell(`Remove-Item C:\\Users\\*\\AppData\\Roaming\\Doorman\\doorman\\guard\\pending\\*`)).toBeDefined();
    expect(shell(`del /q C:\\Users\\wdev\\AppData\\Roaming\\Doorm?n\\doorman\\guard\\policy.json`)).toBeDefined();
  });

  it("holds cmd caret and PowerShell backtick escapes", () => {
    expect(shell(`echo {} > C:\\Users\\wdev\\AppData\\Roaming\\Door^man\\doorman\\guard\\policy.json`)).toBeDefined();
    expect(shell("Set-Content C:\\Users\\wdev\\AppData\\Roaming\\Door`man\\doorman\\guard\\policy.json '{}'")).toBeDefined();
    expect(shell("Set-Content `\n  C:\\Users\\wdev\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json '{}'")).toBeDefined();
  });

  it("does not let a bash-style escaped quote hide a PowerShell command", () => {
    expect(shell(`echo "\\" ; Set-Content ${G}\\policy.json '{}' ; echo "`)).toBeDefined();
  });

  it("does not let cmd's literal apostrophe hide a redirect", () => {
    expect(shell(`echo don't > "${G}\\policy.json"`)).toBeDefined();
  });
});

describe("guardSelfWrite on Windows — writers PowerShell hides", () => {
  it("holds paths assembled with Join-Path or string concatenation", () => {
    expect(shell(`Set-Content (Join-Path $env:APPDATA 'Doorman\\doorman\\guard\\policy.json') '{}'`)).toBeDefined();
    expect(shell(`$p = Join-Path $env:APPDATA 'Doorman\\doorman\\guard'; Set-Content "$p\\policy.json" '{}'`)).toBeDefined();
    expect(shell(`Set-Content ($env:APPDATA + '\\Doorman\\doorman\\guard\\policy.json') '{}'`)).toBeDefined();
  });

  it("holds .NET and method-call writes", () => {
    expect(shell(`[IO.File]::WriteAllText('${G}\\policy.json', '{}')`)).toBeDefined();
    expect(shell(`[System.IO.File]::WriteAllText("$env:APPDATA\\Doorman\\doorman\\guard\\policy.json", '{}')`)).toBeDefined();
    expect(shell(`(Get-Item '${G}\\policy.json').Delete()`)).toBeDefined();
  });

  it("holds a writer hidden inside a reader's subexpression or a string's $( )", () => {
    expect(shell(`Get-Content (Remove-Item '${G}\\policy.json')`)).toBeDefined();
    expect(shell(`Write-Output "$(Set-Content '${G}\\policy.json' '{}')"`)).toBeDefined();
  });

  it("holds guard paths piped into a cmdlet that acts on them", () => {
    expect(shell(`Get-ChildItem '${G}\\pending' | Remove-Item`)).toBeDefined();
    expect(shell(`Get-Item '${G}\\policy.json' | Set-Content -Value '{}'`)).toBeDefined();
    expect(shell(`Get-ChildItem '${G}' | ForEach-Object { $_.Delete() }`)).toBeDefined();
    expect(shell(`gci '${G}' | % { ri $_ }`)).toBeDefined();
  });

  it("holds an -EncodedCommand that names the directory", () => {
    const script = Buffer.from(`Set-Content '${G}\\policy.json' '{}'`, "utf16le").toString("base64");
    expect(shell(`powershell -NoProfile -EncodedCommand ${script}`)).toBeDefined();
    expect(shell(`pwsh -enc ${script}`)).toBeDefined();
  });

  it("holds links and process starts that name the directory", () => {
    expect(shell(`cmd /c mklink /J C:\\tmp\\g "${G}"`)).toBeDefined();
    expect(shell(`New-Item -ItemType Junction -Path C:\\tmp\\g -Target '${G}'`)).toBeDefined();
    expect(shell(`Start-Process cmd -ArgumentList '/c del ${G}\\policy.json'`)).toBeDefined();
    expect(shell(`wsl rm /mnt/c/Users/wdev/AppData/Roaming/Doorman/doorman/guard/policy.json`)).toBeDefined();
  });

  it("holds a PowerShell provider-qualified path, a path list and a splat", () => {
    expect(shell(`Set-Content -Path "FileSystem::${G}\\policy.json" -Value '{}'`)).toBeDefined();
    expect(shell(`Set-Content -Path "Microsoft.PowerShell.Core\\FileSystem::${G}\\policy.json" -Value '{}'`)).toBeDefined();
    expect(shell(`Set-Content -Path C:\\tmp\\a,${G}\\policy.json -Value '{}'`)).toBeDefined();
    expect(shell(`$a = @{ Path = '${G}\\policy.json'; Value = '{}' }; Set-Content @a`)).toBeDefined();
    expect(shell(`New-PSDrive -Name Q -PSProvider FileSystem -Root '${G}'; Set-Content Q:\\policy.json '{}'`)).toBeDefined();
    expect(shell(`cmd /c "set P=${G}&& echo {} > %P%\\policy.json"`)).toBeDefined();
  });

  it("holds downloaders, archivers and interpreters writing there", () => {
    expect(shell(`Invoke-WebRequest https://x.test/p.json -OutFile "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`curl.exe -o"${G}\\policy.json" https://x.test/p.json`)).toBeDefined();
    expect(shell(`tar -xf C:\\tmp\\x.tar -C "${G}"`)).toBeDefined();
    expect(shell(`Expand-Archive C:\\tmp\\x.zip -DestinationPath '${G}' -Force`)).toBeDefined();
    expect(shell(`node -e "require('fs').writeFileSync('C:\\\\Users\\\\wdev\\\\AppData\\\\Roaming\\\\Doorman\\\\doorman\\\\guard\\\\policy.json', '{}')"`)).toBeDefined();
    expect(shell(`python -c "open(r'${G}\\policy.json','w').write('{}')"`)).toBeDefined();
  });

  it("holds names that differ only where NTFS case folding ignores it", () => {
    expect(write("C:\\Users\\wdev\\AppData\\Roamıng\\Doorman\\doorman\\guard\\policy.json")).toBeDefined();
    expect(write("C:\\Uſers\\wdev\\AppData\\Roaming\\Doorman\\doorman\\guard\\policy.json")).toBeDefined();
  });
});

/** A guard directory below no known root, so the Join-Path tail rule cannot
 * fire: each mechanism below has to hold on its own. */
describe("guardSelfWrite on Windows — each mechanism on its own", () => {
  const D = "D:\\tools\\doorman-guard";
  const bare = (command: string, cwd = CWD) => guardSelfWrite("Bash", { command }, cwd, [D], HOME, WIN);

  it("reads PowerShell pipelines, method calls, subexpressions and encoded commands", () => {
    expect(bare(`Get-ChildItem '${D}\\pending' | Remove-Item`)).toBeDefined();
    expect(bare(`Get-ChildItem '${D}' | ForEach-Object { $_.Delete() }`)).toBeDefined();
    expect(bare(`[IO.File]::WriteAllText('${D}\\policy.json', '{}')`)).toBeDefined();
    expect(bare(`(Get-Item '${D}\\policy.json').Delete()`)).toBeDefined();
    expect(bare(`Get-Content (Remove-Item '${D}\\policy.json')`)).toBeDefined();
    expect(bare(`Write-Output "$(Set-Content '${D}\\policy.json' '{}')"`)).toBeDefined();
    const script = Buffer.from(`Set-Content '${D}\\policy.json' '{}'`, "utf16le").toString("base64");
    expect(bare(`powershell -EncodedCommand ${script}`)).toBeDefined();
  });

  it("reads the command as PowerShell and as cmd, not only as bash", () => {
    expect(bare(`echo "\\" ; Set-Content ${D}\\policy.json '{}' ; echo "`)).toBeDefined();
    expect(bare(`echo don't > "${D}\\policy.json"`)).toBeDefined();
    expect(bare("Set-Content `\n  D:\\tools\\doorman-guard\\policy.json '{}'")).toBeDefined();
    expect(bare(`echo {} > D:\\tools\\door^man-guard\\policy.json`)).toBeDefined();
  });

  it("still lets it be read, piped into readers", () => {
    expect(bare(`Get-Content '${D}\\policy.json' | ConvertFrom-Json`)).toBeUndefined();
    expect(bare(`cat '${D}\\policy.json' | jq '{a: .x}'`)).toBeUndefined();
    expect(bare(`Get-ChildItem '${D}\\pending' | Select-Object Name`)).toBeUndefined();
  });
});

describe("guardSelfWrite on Windows — what stays allowed", () => {
  it("lets the guard directory be read", () => {
    expect(guardSelfWrite("Read", { file_path: `${G}\\policy.json` }, CWD, [G], HOME, WIN)).toBeUndefined();
    expect(shell(`Get-Content "${G}\\policy.json"`)).toBeUndefined();
    expect(shell(`gc "${G}\\spool.jsonl" -Tail 20`)).toBeUndefined();
    expect(shell(`type "${G}\\policy.json"`)).toBeUndefined();
    expect(shell(`cat "${GF}/policy.json"`)).toBeUndefined();
    expect(shell(`cat /c/Users/wdev/AppData/Roaming/Doorman/doorman/guard/spool.jsonl | head -5`)).toBeUndefined();
    expect(shell(`Get-ChildItem "${G}\\pending"`)).toBeUndefined();
    expect(shell(`dir "${G}"`)).toBeUndefined();
    expect(shell(`Select-String -Path "${G}\\spool.jsonl" -Pattern held`)).toBeUndefined();
    expect(shell(`findstr held "${G}\\spool.jsonl"`)).toBeUndefined();
    expect(shell(`Get-Content "${G}\\policy.json" | ConvertFrom-Json`)).toBeUndefined();
    expect(shell(`Test-Path "$env:APPDATA\\Doorman\\doorman\\guard\\policy.json"`)).toBeUndefined();
    expect(shell(`Get-Content (Join-Path $env:APPDATA 'Doorman\\doorman\\guard\\policy.json')`)).toBeUndefined();
    expect(shell(`Get-Content "${G}\\policy.json" > C:\\tmp\\policy-copy.json`)).toBeUndefined();
  });

  it("lets a sibling whose name starts with the directory's be written", () => {
    expect(write(`${G}-backup\\policy.json`)).toBeUndefined();
    expect(shell(`echo {} > "${G}-backup\\policy.json"`)).toBeUndefined();
    expect(shell(`Set-Content "${G}2\\policy.json" '{}'`)).toBeUndefined();
    expect(shell(`Copy-Item x "$env:APPDATA\\Doorman\\doorman\\guard-backup\\policy.json"`)).toBeUndefined();
    expect(shell(`cmd /c "echo {} > %APPDATA%\\Doorman\\doorman\\guard-backup\\policy.json"`)).toBeUndefined();
    expect(write("C:\\Users\\wdev\\AppData\\Roaming\\Doorman\\doorman\\policy.json")).toBeUndefined();
  });

  it("lets everything else be written", () => {
    expect(write("C:\\repo\\policy.json")).toBeUndefined();
    expect(write("policy.json")).toBeUndefined();
    expect(shell(`echo {} > policy.json`)).toBeUndefined();
    expect(shell(`Set-Content -Path .\\guard\\policy.json -Value '{}'`)).toBeUndefined();
    expect(shell(`Set-Content -Path C:\\repo\\config.json -Value '{"a":1}'`)).toBeUndefined();
    expect(shell(`powershell -Command "Set-Content -Path 'C:\\repo\\policy.json' -Value '{}'"`)).toBeUndefined();
    expect(shell(`cmd /c "echo {} > %APPDATA%\\Other\\policy.json"`)).toBeUndefined();
    expect(shell(`cd C:\\repo\\sub; Set-Content policy.json '{}'`)).toBeUndefined();
    expect(shell(`npm test 2>&1 | Tee-Object -FilePath C:\\tmp\\out.txt`)).toBeUndefined();
    expect(shell(`Get-ChildItem C:\\repo | Remove-Item -WhatIf`)).toBeUndefined();
    expect(shell(`git -C C:\\repo status`)).toBeUndefined();
  });
});

describe("guardSelfWrite on Windows — copies out of the directory", () => {
  it("lets a copy whose destination is outside pass, whichever program copies", () => {
    expect(shell(`cp "${G}\\spool.jsonl" C:\\wtest\\spool-copy`)).toBeUndefined();
    expect(shell(`cp -r "${GF}/pending" /c/wtest/`)).toBeUndefined();
    expect(shell(`cp -f "${G}\\spool.jsonl" C:\\wtest\\spool-copy`)).toBeUndefined();
    expect(shell(`Copy-Item -Path "${G}\\spool.jsonl" -Destination C:\\wtest\\spool-copy`)).toBeUndefined();
    expect(shell(`Copy-Item -Destination C:\\wtest\\spool-copy "${G}\\spool.jsonl"`)).toBeUndefined();
    expect(shell(`Copy-Item -LiteralPath:"${G}\\spool.jsonl" -Dest C:\\wtest -Force`)).toBeUndefined();
    expect(shell(`copy "${G}\\spool.jsonl" C:\\wtest\\spool-copy`)).toBeUndefined();
    expect(shell(`copy /Y "%APPDATA%\\Doorman\\doorman\\guard\\spool.jsonl" C:\\wtest\\`)).toBeUndefined();
    expect(shell(`xcopy "${G}\\spool.jsonl" C:\\wtest\\ /Y`)).toBeUndefined();
    expect(shell(`robocopy "${G}" C:\\wtest spool.jsonl /NJH`)).toBeUndefined();
  });

  it("lets a POSIX guard directory be copied from under Windows rules too", () => {
    const posixGuard = "/Users/u/Library/Application Support/Doorman/doorman/guard";
    const onWindows = (command: string) => guardSelfWrite("Bash", { command }, "/repo", [posixGuard], "/Users/u", { platform: "win32", env: {} });
    expect(onWindows(`cp "${posixGuard}/spool.jsonl" /tmp/spool-copy`)).toBeUndefined();
    expect(onWindows(`cp -t /tmp '${posixGuard}/spool.jsonl'`)).toBeUndefined();
    expect(onWindows(`cp /tmp/evil.js "${posixGuard}/guard.js"`)).toBeDefined();
    expect(onWindows(`cp -t '${posixGuard}/pending' x.reply.json`)).toBeDefined();
  });

  it("still holds a copy into it, by any reading of the words", () => {
    expect(shell(`cp "${G}\\spool.jsonl" "${G}\\pending\\a.reply.json"`)).toBeDefined();
    expect(shell(`Copy-Item "${G}\\spool.jsonl" -Destination "${G}\\pending\\a.reply.json"`)).toBeDefined();
    expect(shell(`Copy-Item -Destination:"${G}\\policy.json" C:\\tmp\\x.json`)).toBeDefined();
    expect(shell(`copy C:\\tmp\\x.json + C:\\tmp\\y.json "${G}\\policy.json"`)).toBeDefined();
    expect(shell(`copy /b "${G}\\policy.json" +,,`)).toBeDefined();
    expect(shell(`robocopy C:\\tmp "${G}\\pending"`)).toBeDefined();
    expect(shell(`robocopy "${G}" C:\\wtest /SAVE:${G}\\policy`)).toBeDefined();
    expect(shell(`cd "${G}"; Copy-Item C:\\tmp\\x.json .`)).toBeDefined();
  });

  it("holds a copy with no destination when the working directory is the guard directory", () => {
    expect(shell(`copy C:\\tmp\\policy.json`, G)).toBeDefined();
    expect(shell(`xcopy C:\\tmp\\policy.json`, G)).toBeDefined();
    expect(shell(`Copy-Item C:\\tmp\\policy.json`, G)).toBeDefined();
    expect(shell(`Copy-Item C:\\tmp\\policy.json`)).toBeUndefined();
  });
});

describe("guardSelfWrite on Windows — what the hold names", () => {
  it("names the path with its drive and case, variables expanded", () => {
    expect(shell(`cmd /c "echo {} > %APPDATA%\\Doorman\\doorman\\guard\\policy.json"`)).toBe(`${G}\\policy.json`);
    expect(shell(`echo {} > %APPDATA%\\Doorman\\doorman\\guard\\policy.json`)).toBe(`${G}\\policy.json`);
    expect(shell(`powershell -Command "Remove-Item '${GF}/pending/x.json'"`)).toBe(`${G}\\pending\\x.json`);
  });
});
