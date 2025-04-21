import typer
from rich.console import Console
from app.csp_generator import generate_csp_header

app = typer.Typer()
console = Console()

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    # If no subcommand was provided, show help and exit
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        raise typer.Exit()

@app.command()
def generate(path: str = typer.Option(..., prompt=True, help="Path to your website directory."),
             output: str = typer.Option("csp_headers.conf", help="Output CSP header file.")):
    console.print("[bold cyan]Generating CSP headers...[/bold cyan]")
    try:
        csp_header, details = generate_csp_header(path)
        with open(output, "w") as file:
            file.write(csp_header)
        console.print(f"[green]✅ CSP headers successfully written to {output}.[/green]")
        for detail in details:
            console.print(detail)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")


if __name__ == "__main__":
    app()
