import asyncio
import concurrent.futures
from rich.console import Console

console = Console()

def run_in_thread(func, *args):
    """Run a blocking function in a thread pool"""
    return func(*args)

async def run_async(func, *args):
    """Run blocking function asynchronously"""
    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        result = await loop.run_in_executor(pool, func, *args)
    return result

async def run_parallel(tasks: list) -> list:
    """Run multiple tasks in parallel"""
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results
