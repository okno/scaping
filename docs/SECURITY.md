# Security boundaries and lifecycle

[English](SECURITY.md) · [Italiano](SECURITY.it.md) · [README](../README.md)

## Resident application and input

The manifest requests `asInvoker`. The interface and ping monitor do not require administrator privileges. The target is a single validated numeric IPv4 address; hostnames, subnets, lists, and commands are rejected. Each scan copies its target and language from the configuration when it starts.

Nmap child processes use `CreateProcessW` with an absolute executable path and Windows argument quoting. The temporary worker is launched with `ShellExecuteExW` and the `runas` verb. No command passes through a shell, `system()`, `cmd.exe`, or PowerShell. Profiles accept no extra options through IPC or configuration.

A manually selected Nmap path is checked for a local PE executable named `nmap.exe` and queried with `--version`. Selecting an executable authorizes it to run with the user's privileges. Automatic detection uses only `Program Files\Nmap` and checks that the installation is protected; it does not search the working directory or PATH.

XML is read from an immutable copy with a 64 MiB limit. Only the exact inert DOCTYPE normally emitted by Nmap is removed; all other DTD and entity declarations are rejected. XmlLite prohibits DTDs and uses a null resolver. Depth, attributes, and results are bounded. Protocols, ports, counts, the target, and successful completion are checked before full coverage is declared.

Untrusted stdout, stderr, and banners are sanitized for display. A passive banner does not automatically become a service identification. Original output and reports remain under `data`; interface and IPC buffers are bounded.

## Configuration and language

Configuration schema version 2 stores the language as `it` or `en`. Version 1 configuration files are loaded in Italian while preserving the target and all other settings. Migration is performed in memory, with schema version 2 written on the next successful atomic save. Changing the language does not select a new target.

The initial, unconfigured state allows saving a language choice with an empty IP and produces no network traffic. Once a target is configured, applying settings requires a valid IPv4 address. A running scan keeps both its original target and language. Changing the interface language does not alter its work or rewrite previously collected output. Protocol tokens, process arguments, XML data, banners, and external tool output are never translated.

## Temporary UAC worker

The worker exists only for a phase that needs additional privileges. Its command line accepts the parent's PID, creation time, and a nonce. Its channel accepts only a versioned request with an IPv4 address, a validated language identifier, and a fixed profile. It accepts no executable paths, output paths, or free-form arguments.

The named pipe uses a random nonce and an ACL restricted to the current user, rejects remote clients, and verifies peer PIDs. The worker checks that its parent is alive and has the same SID, executable path, and expected creation time. The connection uses an SQOS level that prevents the unelevated server from impersonating the elevated token.

Elevation requires the administrative token of the **same user**. Consent supplied with a different administrator account is intentionally rejected. The application does not switch accounts or relax these checks.

The worker independently selects elevated Nmap from the protected default installation directory. The owner and DACL of the directory, executable, and installation files must be administratively controlled. Reparse points and unverifiable ACLs are rejected. A present but invalid signature is rejected. An unsigned Nmap installed by an administrator may be accepted based on protection of its entire installation tree; this ACL check is not described as a digital signature.

The worker builds a reduced environment, writes XML to a private administrative temporary directory, and returns it in bounded frames. The unelevated parent saves the requested report, avoiding privileged writes to user-supplied paths.

Each child is created suspended, assigned to a Job Object with `KILL_ON_JOB_CLOSE`, and then started. The inherited handle list is explicit. The worker monitors its parent and IPC connection: cancellation, disconnection, or parent exit terminates the Job and its children. An unanswered UAC prompt does not block interface shutdown. The launch uses isolated shared state; if consent arrives late, the worker must still find the original parent and pipe valid before proceeding.

## Explicit limitations

- SCAPING queries Npcap; it does not install or start it. Service availability does not guarantee permission to open a device, so Nmap's actual result remains decisive.
- Declined UAC, missing dependencies, invalid XML, or a failed phase produces a partial result. UDP results are never inferred from silence on a native socket.
- SCAPING does not use a documented ICMP cancellation mechanism. After **Exit**, the process may wait for the remaining timeout of its one outstanding ping: initially 800 ms, up to the configured limit of 60 seconds. The tray icon and windows are removed and the scan is cancelled; ICMP buffers and handles remain valid until the operating system completes the request.
- The application does not promise anonymity of the Git repository owner's account. Its privacy measures cover repository contents, configuration, commit metadata, and packages.

## Review before publication

Run `scripts\privacy-check.ps1` after staging. With `-GitleaksPath <path>`, Gitleaks also checks the staged diff and history. Manually review tracked files, author and committer metadata, and the package allow-list as well. Do not add local settings, reports, local test output, or conversations to the repository.
