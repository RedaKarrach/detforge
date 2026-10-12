# DetForge rules

One row per rule. Every rule must be defensible: what it looks for, what legitimately trips it,
and how an attacker gets around it.

| Rule | Technique | Logic | False positives | Evasions |
|------|-----------|-------|-----------------|----------|
| [powershell_encoded_command](../rules/windows/execution/powershell_encoded_command.yml) | T1059.001 PowerShell (execution) | Process creation where the binary is PowerShell (Image ends with `\powershell.exe`/`\pwsh.exe`, or OriginalFileName `PowerShell.EXE`/`pwsh.dll`, so renamed copies still match) AND the command line contains `-EncodedCommand` or any accepted abbreviation (`-e`, `-ec`, `-en`, `-enc` ... `-encodedcommand`), each surrounded by spaces; `windash` also matches the `/`, en-dash, em-dash and horizontal-bar forms. | SCCM, Intune and other deployment or RMM tools that launch encoded scripts; some vendor installers. | Passing the payload without the parameter: piping it on stdin (`powershell -`), `-Command` with `[Convert]::FromBase64String` decoded inline, or reading it from an environment variable or file. Hosting the PowerShell engine in a custom binary (System.Management.Automation) with no powershell.exe/pwsh.dll process. Flag followed by a tab or other non-space whitespace instead of a space. |
