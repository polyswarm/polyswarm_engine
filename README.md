

## Analyzers

This tool wraps the PolySwarm engine machinery, allowing you (the engine developer)
to run a custom-built python script, web API, software running on another machine, etc.

- Scanner functions should be able to depend on an execution environment which is initialized exactly once for each scanner & shares nothing between individual processes / tasks / threads / etc.
- Scanners should support initializer / setup() which is run only once, which can write to a safe data store readable (but not necessarily writable) from worker children.
- Scanner's interface functions should be segregated, with many specific interfaces rather than one general-purpose interface. each of which should have a single responsibility
- we should depend upon an abstraction of scanner interfaces, not concrete engine function internals.
- It is better to split scanning up into as many small tasks as there are responsibilities for steps of execution.
- engines shouldn't tamper with the internal implementation of client-supplied functions (corollary: functions defined by the author should be callable from within their debugger, ipython, e.g. as Sam's set_handler does this) e.g engine functions should be callable "as they are", without setting up external state.
- Ideally, scanner functions should be pure. They should never keep internal state.
- Engines should be able to kick-off scans which are entirely autonomous processes, e.g can submit their bounty response without external code waiting on that result (e.g ignoring it's result).
- Both the author of the engine interface & the users of it should be able to add callbacks which are triggered on errors and success (with the results included).
- Engines should, in exceptional cases, have the ability to extend the core classes without reimplementing everything from the ground up.

## CLI

### `analyze`

The `analyze` command creates a `Bounty` from a file, pipe or URL

```console
[zv@fedora] Development/polyswarm_engine $ ./examples/nanoav/nanoav.py analyze -v --backend local resource/malicious/pe/*
Starting NANO Antivirus JSON RPC server...
    OS environment:  WINE
    The installation path:  /home/zv/Development/microengines/microengines/nanoav/vendor/nanoavsdk
    The executable file path:  /home/zv/Development/microengines/microengines/nanoav/vendor/nanoavsdk/bin/nanoavc.exe
JSON RPC server initialization started (PID: 2142926)...
JSON RPC server initialization completed...
-------------------------resource/malicious/pe/Abel.exe-------------------------
Bounty: {
  "id": 3890646043,
  "artifact_uri": "file:///home/zv/Development/psengine-test/psengine_test/resource/malicious/pe/Abel.exe",
  "artifact_type": "file",
  "sha256": "a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427",
  "mimetype": "application/x-dosexec"
}
Analysis: {
  "bid": 18446744073709551615,
  "result": "malicious",
  "result_name": "Riskware.Win32.Cain.ecncwa",
  "product": "NANO Antivirus",
  "vendor": "NanoAV",
  "analysis_engine_version": "1.0.146.90945",
  "analysis_definition_version": "0.14.45.23447"
}
------------------------resource/malicious/pe/conficker-------------------------
Bounty: {
  "id": 474020256,
  "artifact_uri": "file:///home/zv/Development/psengine-test/psengine_test/resource/malicious/pe/conficker",
  "artifact_type": "file",
  "sha256": "523d40c69b0972ddeff0682fcb569e8a346cf10b2894479ab227bbb24e19846e",
  "mimetype": "application/x-dosexec"
}
Analysis: {
  "bid": 18446744073709551615,
  "result": "malicious",
  "result_name": "Trojan.Win32.Kido.bvftw",
  "product": "NANO Antivirus",
  "vendor": "NanoAV",
  "analysis_engine_version": "1.0.146.90945",
  "analysis_definition_version": "0.14.45.23447"
}
JSON RPC server has finished.
```

### `worker`

You can start a `celery` worker with the `worker` command


```console
[zv@fedora] Development/polyswarm_engine $ ./examples/nanoav/nanoav.py worker
Starting NANO Antivirus JSON RPC server...
    OS environment:  WINE
    The installation path:  /home/zv/Development/microengines/microengines/nanoav/vendor/nanoavsdk
    The executable file path:  /home/zv/Development/microengines/microengines/nanoav/vendor/nanoavsdk/bin/nanoavc.exe
JSON RPC server initialization started (PID: 2143537)...
JSON RPC server initialization completed...

 -------------- celery@fedora v5.2.1 (dawn-chorus)
--- ***** -----
-- ******* ---- Linux-5.14.18-100.fc33.x86_64-x86_64-with-glibc2.32 2022-02-10 17:49:08
- *** --- * ---
- ** ---------- [config]
- ** ---------- .> app:         nanoav:0x7f886432ef70
- ** ---------- .> transport:   amqp://guest:**@localhost:5672//
- ** ---------- .> results:     redis://localhost/
- *** --- * --- .> concurrency: 8 (prefork)
-- ******* ---- .> task events: OFF (enable -E to monitor tasks in this worker)
--- ***** -----
 -------------- [queues]
                .> celery           exchange=celery(direct) key=celery
```

After you've started a `celery` worker, you can provide `--backend celery` to the `analyze` command t

```console
[zv@fedora] Development/psengine $ ./examples/nanoav/nanoav.py analyze -v --backend celery resource/malicious/pe/*
-------------------------resource/malicious/pe/Abel.exe-------------------------
Bounty: {
  "id": 3890646043,
  "artifact_uri": "file:///home/zv/Development/psengine-test/psengine_test/resource/malicious/pe/Abel.exe",
  "artifact_type": "file",
  "sha256": "a709f37b3a50608f2e9830f92ea25da04bfa4f34d2efecfd061de9f29af02427",
  "mimetype": "application/x-dosexec"
}
Analysis: {
  "bid": 18446744073709551615,
  "result": "malicious",
  "result_name": "Riskware.Win32.Cain.ecncwa",
  "product": "NANO Antivirus",
  "vendor": "NanoAV",
  "analysis_engine_version": "1.0.146.90945",
  "analysis_definition_version": "0.14.45.23447"
}
------------------------resource/malicious/pe/conficker-------------------------
Bounty: {
  "id": 474020256,
  "artifact_uri": "file:///home/zv/Development/psengine-test/psengine_test/resource/malicious/pe/conficker",
  "artifact_type": "file",
  "sha256": "523d40c69b0972ddeff0682fcb569e8a346cf10b2894479ab227bbb24e19846e",
  "mimetype": "application/x-dosexec"
}
Analysis: {
  "bid": 18446744073709551615,
  "result": "malicious",
  "result_name": "Trojan.Win32.Kido.bvftw",
  "product": "NANO Antivirus",
  "vendor": "NanoAV",
  "analysis_engine_version": "1.0.146.90945",
  "analysis_definition_version": "0.14.45.23447"
}
```

### `command`

You can access all of the commands exposed by an engine through `command`

```console
[zv@fedora] Development/polyswarm_engine $ ./examples/nanoav/nanoav.py commands --help
Usage: nanoav.py commands [OPTIONS] COMMAND [ARGS]...

  Engine commands

Options:
  --help  Show this message and exit.

Commands:
  info       Engine & signature versions
  scan_file  Scan filename
#
```

### `webhook`

`webhook` starts an HTTP server you can submit bounty webhook test requests to

```console
[zv@fedora] Development/polyswarm_engine $ ./examples/nanoav/nanoav.py webhook --help
Usage: nanoav.py webhook [OPTIONS]

  Bounty webhooks

Options:
  -p, --port INTEGER              Server port
  --backend [local|process|celery]
                                  [required]
  --help                          Show this message and exit.

```


### Config

#### Environment Variables

##### `TMPPREFIX`
`TMPPREFIX` specifies a directory prefix to use for all temporary files created by `polyswarm_engine`. `polyswarm_engine` (and most other Unix programs) will also respect `TMPDIR` and use it's value to denote the scratch area instead of the default.

##### Engine

Engines should prefer to specify files (binaries, license files, DLLs, etc.) as paths relative to a well-known base directory variable.

###### `${ENGINE}_PATH`
Engine executables should be stored  here (analogous to `/usr/bin`)

###### `${ENGINE}_SDK_HOME`
Engine-specific libraries, shared objects & DLLs (analogous to `/usr/lib`)

###### `${ENGINE}_SECRETS_HOME`
License files and other secrets (analogous to `/usr/bin`)

###### `${ENGINE}_CONFIG_HOME`
Engine-specific configurations (analogous to `/etc`)

###### `${ENGINE}_CACHE_HOME`
Non-essential (cached) data (analogous to `/var/cache`)

###### `${ENGINE}_DATA_HOME`
Engine-specific data files (analogous to `/usr/share`).

###### `${ENGINE}_STATE_HOME`
Contains state data that should persist between restarts:

- Logs
- Rate-limiting data
- Telemetry
- Current application state (if running as a daemon)

###### `${ENGINE}_RUNTIME_DIR`
Used for non-essential, engine data files such as sockets, named pipes, etc. (analogous to `/var/run`)

- Not required to have a default value; warnings should be issued if not set or equivalents provided.
- Must be owned by the user with an access mode of `0700`.
- May be subject to periodic cleanup.
- This directory **MUST** be on a local file system which supports:
    + symbolic links
    + proper permissions
    + file locking
    + sparse files
    + memory mapping
    + file change notifications

###### Files

Your configuration should strive to specify particular relative to well-known base directory variables shown above. If your implementation prefers absolute paths to executable or configuration files, you can still use a few well-known names

###### `${ENGINE}_SCANNER`
Path to the executable used for scanning binaries

###### `${ENGINE}_UPDATER`
Path to the executable used for updating engine definitions

##### System

##### `TMPDIR`
`TMPDIR` is the canonical environment variable in POSIX systems that should be used to specify a temporary directory for scratch space. `polyswarm_engine` (and most other Unix programs) will honor this setting and use it's value to denote the scratch area for temporary files instead of the common default of `/tmp`

##### `LC_ALL`
Locales can be especially confusing when using PE executables from within a POSIX system with WINE. Many WinNT applications are compiled to use UCS-2 / 1252 without regard for locale configuration (in addition to using `CRLF` newlines)

##### `TZ`
Timezone

#### Wine

##### `WINELOADER`
Specifies the path and name of the Wine binary to use to launch new Windows processes.

If not set and not running on Windows, this will look for a file named "wine" in `PATH`

##### `PERSISTENT_WINESERVER`
If set to any non-`0` value, a `wineserver` is started that stays around forever.

`wineserver` is normally launched automatically when starting `wine`, however,
it is useful to start `wineserver` explicitly with an unlimited persistence
delay, this avoids the cost of shutting down and starting again when wine-loaded
programs are launched in quick succession.

###### Killing

You can kill a persistent `wineserver` with `--kill`

```console
swarm@engine:~$ wineserver --kill
```


### Fetching

Bounties are delivered with an Artifact URI, defining where an Artifact's
contents can be found. This can reference an HTTP/HTTPS/data URI and a `file://`
when using your engine locally:

| Scheme | Example URI                                                                                             |
| ---    | -----------                                                                                             |
| file   | file:///usr/bin/ls                                                                                      |
| data   | data:text/uri-list;base64,aHR0cDovL2dvb2dsZS5jb20v                                                      |
| https  | https://resource.polyswarm.io/artifact/b1b249f39beaa9360abe95570560437f41e0a0f8bb7e3c74546078996d80c5ff |



#### Categories & Mimetypes

| Category         | Mimetype                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| -------------    | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| android          | `application/vnd.android.package-archive`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| archives         | `application/java-archive` `application/x-tar` `application/zip` `application/x-compressed-zip` `application/gzip` `application/vnd.rar` `application/x-bzip2` `application/x-xz` `application/octet-stream` `application/x-7z-compressed`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| elf              | `application/x-executable`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| flash            | `application/x-shockwave-flash`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| font             | `application/vnd.ms-fontobject` `application/vnd.oasis.opendocument.text` `font/otf` `font/ttf` `font/woff` `font/woff2`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| linux            | elf + `application/x-cpio` `application/x-rpm` `application/x-dpkg` `application/octet-stream`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| mach-o           | `application/x-mach-binary` `application/octet-stream`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| office (abiword) | `application/x-abiword`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| office (etc)     | `text/calendar`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| office (ms)      | `application/msword` `application/vnd.ms-excel` `application/vnd.ms-excel.addin.macroEnabled.12` `application/vnd.ms-excel.sheet.binary.macroEnabled.12` `application/vnd.ms-excel.sheet.macroEnabled.12` `application/vnd.ms-excel.template.macroEnabled.12` `application/vnd.ms-powerpoint` `application/vnd.ms-powerpoint.addin.macroEnabled.12` `application/vnd.ms-powerpoint.presentation.macroEnabled.12` `application/vnd.ms-powerpoint.slideshow.macroEnabled.12` `application/vnd.ms-word.document.macroEnabled.12` `application/vnd.ms-word.template.macroEnabled.12` `application/vnd.openxmlformats-officedocument.presentationml.presentation` `application/vnd.openxmlformats-officedocument.presentationml.slideshow` `application/vnd.openxmlformats-officedocument.presentationml.template` `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` `application/vnd.openxmlformats-officedocument.spreadsheetml.template` `application/vnd.openxmlformats-officedocument.wordprocessingml.document` `application/vnd.openxmlformats-officedocument.wordprocessingml.template` |
| office (open)    | `application/vnd.oasis.opendocument.chart-template` `application/vnd.oasis.opendocument.chart` `application/vnd.oasis.opendocument.database` `application/vnd.oasis.opendocument.formula` `application/vnd.oasis.opendocument.graphics-template` `application/vnd.oasis.opendocument.graphics` `application/vnd.oasis.opendocument.image-template` `application/vnd.oasis.opendocument.image` `application/vnd.oasis.opendocument.presentation-template` `application/vnd.oasis.opendocument.presentation` `application/vnd.oasis.opendocument.spreadsheet-template` `application/vnd.oasis.opendocument.spreadsheet` `application/vnd.oasis.opendocument.text-master` `application/vnd.oasis.opendocument.text-template` `application/vnd.oasis.opendocument.text-web` `application/vnd.oasis.opendocument.text` `application/vnd.openofficeorg.extension`                                                                                                                                                                                                                                                  |
| osx              | mach-o + `application/octet-stream`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| pdf              | `application/pdf` `text/plain` `application/octet-stream`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| pe               | `application/x-dosexec`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| rtf              | `application/rtf` `text/plain`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| text & script    | `application/x-httpd-php` `application/javascript` `application/json` `application/x-sh` `application/x-csh` `text/html` `text/plain` `text/x-python` `text/xml` `text/plain` `application/vnd.coffeescript`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 |
| winnt            | pe + `text/plain` `application/octet-stream` `image/vnd.microsoft.icon` `text/plain`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |

#### 1-100 Scale
| 0-100 Scale | Polyswarm Bid |
|-------------+---------------|
|           0 |             0 |
|          10 |            10 |
|          20 |            20 |
|          30 |            30 |
|          40 |            40 |
|          50 |            50 |
|          60 |            60 |
|          70 |            70 |
|          80 |            80 |
|          90 |            90 |
|         100 |           100 |


#### DNI Scale
Definition: [https://www.dni.gov/files/documents/ICD/ICD%20203%20Analytic%20Standards.pdf]

| DNI Scale                               | Polyswarm Bid |
|-----------------------------------------+---------------|
| Not Specified                           | Not Specified |
| Almost No Chance / Remote               |             5 |
| Very Unlikely / Highly Improbable       |            15 |
| Unlikely / Improbable                   |            30 |
| Roughly Even Chance / Roughly Even Odds |            50 |
| Likely / Probable                       |            70 |
| Very Likely / Highly Probable           |            85 |
| Almost Certain / Nearly Certain         |            95 |
