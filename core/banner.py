from rich.console import Console
from rich.rule import Rule

console = Console()

def show_banner():
    console.print()
    console.print(Rule(style="red"))
    console.print()
    console.print("  [bold red]B u g z B u n n y[/bold red]")
    console.print("  [dim]Hop. Hunt. Hack.[/dim]")
    console.print()
    console.print(Rule(style="red"))
    console.print()
    console.print("  [bold white]Version[/bold white] : [cyan]v2.0.0[/cyan]")
    console.print("  [bold white]Author  [/bold white]: [cyan]Joy Dalal[/cyan]")
    console.print("  [bold white]GitHub  [/bold white]: [cyan]github.com/JOYDALAL7/BugzBunny[/cyan]")
    console.print()
    console.print("  [bold red][!] For authorized testing only[/bold red]")
    console.print()
    console.print(Rule(style="red"))
    console.print()
