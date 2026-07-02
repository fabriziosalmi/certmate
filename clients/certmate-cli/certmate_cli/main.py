"""CertMate CLI — a thin, pleasant terminal front-end over certmate-sdk.

    certmate cert create app.example.com --dns cloudflare --wait
    certmate cert ls
    certmate cert renew app.example.com --force
    certmate audit verify

Connection comes from --url/--token or CERTMATE_URL/CERTMATE_TOKEN.
"""
from __future__ import annotations

import re
from typing import List, Optional

import typer
from rich.console import Console
from rich.table import Table

from certmate import Client, CertMateError, Job

app = typer.Typer(no_args_is_help=True, add_completion=False,
                  help="CertMate — the SSL certificate lifecycle from your terminal.")
cert_app = typer.Typer(no_args_is_help=True, help="Manage certificates.")
dns_app = typer.Typer(no_args_is_help=True, help="DNS providers and accounts.")
audit_app = typer.Typer(no_args_is_help=True, help="Tamper-evident audit trail.")
backup_app = typer.Typer(no_args_is_help=True, help="Backups.")
deploy_app = typer.Typer(no_args_is_help=True, help="Post-issuance deploy hooks.")
app.add_typer(cert_app, name="cert")
app.add_typer(dns_app, name="dns")
app.add_typer(audit_app, name="audit")
app.add_typer(backup_app, name="backup")
app.add_typer(deploy_app, name="deploy")

out = Console()
err = Console(stderr=True)

# A lax hostname/wildcard check for the client-side --dry-run preflight; the
# server is the real authority, this just catches obvious typos before we
# spend an API call.
_DOMAIN_RE = re.compile(
    r"^(\*\.)?([a-zA-Z0-9_](-*[a-zA-Z0-9_])*\.)+[a-zA-Z]{2,}$")


@app.callback()
def _main(
    ctx: typer.Context,
    url: Optional[str] = typer.Option(None, "--url", envvar="CERTMATE_URL",
                                      help="CertMate base URL (default http://localhost:8000)."),
    token: Optional[str] = typer.Option(None, "--token", envvar="CERTMATE_TOKEN",
                                        help="API bearer token."),
):
    ctx.obj = {"url": url, "token": token}


def _client(ctx: typer.Context) -> Client:
    o = ctx.obj or {}
    return Client(o.get("url"), o.get("token"))


def _die(msg: str, code: int = 1):
    err.print(f"[bold red]error[/]: {msg}")
    raise typer.Exit(code)


def _run(fn):
    """Execute an SDK call, turning SDK errors into clean CLI failures."""
    try:
        return fn()
    except CertMateError as e:
        _die(str(e))


def _records(data) -> List[dict]:
    """Coerce a list/dict API response into a list of record dicts."""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for key in ("items", "accounts", "backups", "results", "data", "unified"):
            v = data.get(key)
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
    return []


def _table(records: List[dict], columns: List[str]) -> None:
    """Print a rich table of ``records`` over ``columns`` (missing keys -> '-')."""
    if not records:
        out.print("[dim]nothing to show.[/]")
        return
    table = Table(box=None, header_style="bold")
    for c in columns:
        table.add_column(c.upper())
    for r in records:
        table.add_row(*[str(r.get(c, "-")) for c in columns])
    out.print(table)


# --------------------------------------------------------------------------
# cert
# --------------------------------------------------------------------------

@cert_app.command("ls")
def cert_ls(ctx: typer.Context):
    """List certificates with expiry and status."""
    certs = _run(lambda: _client(ctx).list_certificates())
    if not certs:
        out.print("[dim]No certificates.[/]")
        return
    table = Table(box=None, header_style="bold")
    table.add_column("DOMAIN")
    table.add_column("EXPIRES")
    table.add_column("DAYS", justify="right")
    table.add_column("CA")
    table.add_column("AUTO-RENEW")
    for c in sorted(certs, key=lambda x: (x.days_until_expiry if x.days_until_expiry is not None else 1 << 30)):
        days = c.days_until_expiry
        days_str = "-" if days is None else str(days)
        colour = "green"
        if days is not None:
            colour = "red" if days < 7 else ("yellow" if days < 30 else "green")
        table.add_row(
            c.domain,
            (c.expiry_date or "-")[:10],
            f"[{colour}]{days_str}[/]",
            c.ca_provider or "-",
            "on" if c.auto_renew else ("off" if c.auto_renew is not None else "-"),
        )
    out.print(table)


@cert_app.command("info")
def cert_info(ctx: typer.Context, domain: str):
    """Show a certificate's details."""
    c = _run(lambda: _client(ctx).get_certificate(domain))
    out.print(f"[bold]{c.domain}[/]")
    out.print(f"  expires:     {c.expiry_date or '-'}  "
              f"({c.days_until_expiry if c.days_until_expiry is not None else '?'} days)")
    out.print(f"  CA:          {c.ca_provider or '-'}")
    out.print(f"  DNS:         {c.dns_provider or '-'}")
    out.print(f"  auto-renew:  {c.auto_renew}")
    if c.san_domains:
        out.print(f"  SAN:         {', '.join(c.san_domains)}")
    if c.needs_renewal:
        out.print("  [yellow]needs renewal[/]")


@cert_app.command("create")
def cert_create(
    ctx: typer.Context,
    domain: str,
    dns: Optional[str] = typer.Option(None, "--dns", help="DNS provider (e.g. cloudflare)."),
    ca: Optional[str] = typer.Option(None, "--ca", help="CA provider (e.g. letsencrypt)."),
    san: Optional[str] = typer.Option(None, "--san", help="Comma-separated SAN domains."),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Wait for issuance to finish."),
    dry_run: bool = typer.Option(False, "--dry-run",
                                 help="Validate inputs and preflight the DNS provider WITHOUT issuing."),
):
    """Issue a certificate (async; waits for completion by default)."""
    sans: List[str] = [s.strip() for s in san.split(",")] if san else []
    client = _client(ctx)

    if dry_run:
        problems = []
        if not _DOMAIN_RE.match(domain):
            problems.append(f"domain {domain!r} does not look valid")
        for s in sans:
            if not _DOMAIN_RE.match(s):
                problems.append(f"SAN {s!r} does not look valid")
        if dns:
            res = _run(lambda: client.test_dns_provider(dns))
            ok = bool(res.get("success", res.get("ok", True)))
            msg = res.get("message") or res.get("error") or ("reachable" if ok else "failed")
            out.print(f"DNS provider [bold]{dns}[/]: {'[green]OK[/]' if ok else '[red]FAIL[/]'} — {msg}")
            if not ok:
                problems.append("DNS provider preflight failed")
        else:
            out.print("[dim]No --dns given; skipping provider preflight.[/]")
        if problems:
            _die("dry-run found issues:\n  - " + "\n  - ".join(problems))
        out.print(f"[green]dry-run OK[/] — would issue [bold]{domain}[/]"
                  f"{(' (+' + str(len(sans)) + ' SAN)') if sans else ''}"
                  f"{(' via ' + dns) if dns else ''}{(' on ' + ca) if ca else ''}. Nothing issued.")
        return

    def _issue():
        with out.status(f"Issuing [bold]{domain}[/] …") as status:
            def _progress(j: Job):
                if j.status:
                    status.update(f"Issuing [bold]{domain}[/] … [{j.status}]")
            return client.create_certificate(
                domain, dns_provider=dns, ca_provider=ca, san_domains=sans or None,
                wait=wait, on_progress=_progress)

    job = _run(_issue)
    if wait:
        out.print(f"[green]issued[/] [bold]{domain}[/]"
                  f"{(' (' + job.status + ')') if job.status else ''}.")
    else:
        out.print(f"[yellow]accepted[/] — job [bold]{job.job_id}[/] "
                  f"(poll: certmate cert job {job.job_id}).")


@cert_app.command("job")
def cert_job(ctx: typer.Context, job_id: str):
    """Show the status of an async issuance/renewal job."""
    j = _run(lambda: _client(ctx).get_job(job_id))
    out.print(f"job [bold]{j.job_id}[/]: {j.status or '?'}"
              f"{(' — ' + j.error) if j.error else ''}")


@cert_app.command("renew")
def cert_renew(ctx: typer.Context, domain: str,
               force: bool = typer.Option(False, "--force", help="Force renewal even if not due.")):
    """Renew a certificate."""
    res = _run(lambda: _client(ctx).renew_certificate(domain, force=force))
    if res.get("renewed") is False:
        out.print(f"[yellow]not due[/] — {domain} was not yet due for renewal.")
    else:
        out.print(f"[green]renewed[/] {domain}.")


@cert_app.command("rm")
def cert_rm(ctx: typer.Context, domain: str,
            yes: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation.")):
    """Delete a certificate."""
    if not yes:
        typer.confirm(f"Delete certificate {domain}?", abort=True)
    _run(lambda: _client(ctx).delete_certificate(domain))
    out.print(f"[green]deleted[/] {domain}.")


@cert_app.command("reissue")
def cert_reissue(ctx: typer.Context, domain: str,
                 san: Optional[str] = typer.Option(None, "--san", help="Comma-separated SAN domains.")):
    """Reissue a certificate (e.g. to change its SAN list)."""
    body = {}
    if san is not None:
        body["san_domains"] = [s.strip() for s in san.split(",") if s.strip()]
    _run(lambda: _client(ctx).reissue_certificate(domain, **body))
    out.print(f"[green]reissued[/] {domain}.")


# --------------------------------------------------------------------------
# dns
# --------------------------------------------------------------------------

@dns_app.command("providers")
def dns_providers(ctx: typer.Context):
    """List supported DNS providers."""
    out.print(_run(lambda: _client(ctx).list_dns_providers()))


@dns_app.command("accounts")
def dns_accounts(ctx: typer.Context,
                 provider: Optional[str] = typer.Argument(None, help="Filter by provider.")):
    """List configured DNS accounts."""
    data = _run(lambda: _client(ctx).list_dns_accounts(provider))
    _table(_records(data), ["provider", "account_id", "name", "email"])


@dns_app.command("test")
def dns_test(ctx: typer.Context, provider: str):
    """Preflight a DNS provider (does not issue)."""
    res = _run(lambda: _client(ctx).test_dns_provider(provider))
    ok = bool(res.get("success", res.get("ok", True)))
    msg = res.get("message") or res.get("error") or ("reachable" if ok else "failed")
    out.print(f"[bold]{provider}[/]: {'[green]OK[/]' if ok else '[red]FAIL[/]'} — {msg}")
    if not ok:
        raise typer.Exit(1)


# --------------------------------------------------------------------------
# audit
# --------------------------------------------------------------------------

@audit_app.command("verify")
def audit_verify(ctx: typer.Context):
    """Verify the tamper-evident audit chain."""
    res = _run(lambda: _client(ctx).audit_verify())
    ok = bool(res.get("ok"))
    reason = res.get("reason") or ""
    cp = res.get("checkpoint_verified")
    # "chain file does not exist" / "empty chain" is a fresh instance that has
    # not audited anything yet — benign, not a tamper alarm. Show it neutrally.
    if not ok and any(k in reason.lower() for k in ("does not exist", "empty")):
        out.print(f"audit chain: [dim]none yet[/] — {reason}")
        return
    out.print(f"audit chain: {'[green]intact[/]' if ok else '[red]BROKEN[/]'}"
              f"{(' — ' + reason) if reason else ''}")
    if cp is not None:
        out.print(f"  signed checkpoint: {'[green]verified[/]' if cp else '[dim]not cross-checked[/]'}"
                  f"{(' @ seq ' + str(res.get('checkpoint_seq'))) if res.get('checkpoint_seq') is not None else ''}")
    if not ok:
        raise typer.Exit(1)


# --------------------------------------------------------------------------
# backup
# --------------------------------------------------------------------------

@backup_app.command("ls")
def backup_ls(ctx: typer.Context):
    """List backups."""
    data = _run(lambda: _client(ctx).list_backups())
    # Items are {filename, metadata:{size, created, backup_reason, ...}} — flatten.
    flat = [{**r, **(r.get("metadata") or {})} for r in _records(data)]
    _table(flat, ["filename", "backup_reason", "created", "size"])


@backup_app.command("create")
def backup_create(ctx: typer.Context):
    """Create a backup now."""
    res = _run(lambda: _client(ctx).create_backup())
    name = (res or {}).get("filename") or (res or {}).get("backup") or "ok"
    out.print(f"[green]backup created[/] {name}")


# --------------------------------------------------------------------------
# deploy
# --------------------------------------------------------------------------

@deploy_app.command("run")
def deploy_run(ctx: typer.Context, domain: str):
    """Run the configured deploy hooks for a domain now."""
    res = _run(lambda: _client(ctx).deploy_certificate(domain))
    ok = bool((res or {}).get("ok", True))
    out.print(f"deploy [bold]{domain}[/]: {'[green]ok[/]' if ok else '[red]failed[/]'}"
              f"{(' — ' + str(res.get('message'))) if isinstance(res, dict) and res.get('message') else ''}")
    if not ok:
        raise typer.Exit(1)


# --------------------------------------------------------------------------
# top-level convenience
# --------------------------------------------------------------------------

@app.command("health")
def health(ctx: typer.Context):
    """Check the CertMate instance health."""
    out.print(_run(lambda: _client(ctx).health()))


if __name__ == "__main__":
    app()
