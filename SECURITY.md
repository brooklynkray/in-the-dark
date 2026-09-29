# Security Policy

## Authorised use only

In the Dark is for authorised security testing, education and defensive use
only. Only scan systems you own or have explicit permission to test. You are
responsible for staying within your authorised scope.

## The tool's security model

How In the Dark handles command execution, untrusted tool output, privilege and
file writes is documented in the **Security Design** section of the README. A
report is most useful against that model: for example a way to get user input
into a command, bypass the flag allow-list, escape the results directory, or
misuse the sudo/root path.

## Reporting a vulnerability

Please report privately rather than opening a public issue. Use GitHub's private
vulnerability reporting: the **Security** tab on this repo, then **Report a
vulnerability**.

You'll get an acknowledgement and a fix or explanation as soon as is practical.
Please hold off on public disclosure until it's resolved.

## Supported versions

Fixes are made against the latest state of `main`.
