import asyncio
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.modules.servers.service import ServerService
from app.modules.logs.service import LogService
from app.modules.metrics.service import MetricService
from app.core.database import get_database
from app.core.config import settings
from app.modules.logs.file_watcher import FileWatcherService


scheduler = AsyncIOScheduler()

# --- Semaphore: limits how many servers are processed at once ---
# This prevents overwhelming the system with too many SSH connections.
# Default: 20 concurrent. Override via MAX_CONCURRENT_SERVERS in .env.
_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_SERVERS)


async def _run_with_limit(coro):
    """Wraps a coroutine with the semaphore to limit concurrency."""
    async with _semaphore:
        return await coro


async def job_file_watcher():
    """Runs every 60 seconds to check file offsets"""
    try:
        service = FileWatcherService()
        sources = await service.get_all_sources()
        if not sources:
            return

        print(f"📂 Checking {len(sources)} file sources...")
        tasks = [_run_with_limit(service.process_file_source(source)) for source in sources]
        await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        print(f"❌ File Watcher Failed: {e}")


async def job_health_check():
    """Runs every 60 seconds"""
    try:
        service = ServerService()
        await service.update_all_server_statuses()
    except Exception as e:
        print(f"❌ Health Check Failed: {e}")


async def job_log_collection():
    """Runs every 60 seconds — collects logs from all servers in parallel"""
    try:
        db = get_database()
        service = LogService()

        servers = await db["servers"].find().to_list(length=10000)
        if not servers:
            return

        print(f"📥 Running Auto-Log Collection for {len(servers)} servers...")
        tasks = [
            _run_with_limit(service.collect_logs_from_server(str(server["_id"])))
            for server in servers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Log any individual server failures
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"❌ Log collection failed for {servers[i].get('hostname', 'unknown')}: {result}")

    except Exception as e:
        print(f"❌ Log Collection Failed: {e}")


async def job_metric_collection():
    """Runs every 60 seconds — collects metrics from all servers in parallel"""
    try:
        db = get_database()
        service = MetricService()
        servers = await db["servers"].find().to_list(length=10000)
        if not servers:
            return

        tasks = [
            _run_with_limit(service.collect_metrics(str(server["_id"])))
            for server in servers
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                print(f"❌ Metrics failed for {servers[i].get('hostname', 'unknown')}: {result}")

    except Exception as e:
        print(f"❌ Metric Collection Failed: {e}")


def start_scheduler():
    # Add Health Check (60s)
    scheduler.add_job(job_health_check, "interval", seconds=60)

    # Add Log Collection (60s)
    scheduler.add_job(job_log_collection, "interval", seconds=60)

    # Add Metric Collection (60s)
    scheduler.add_job(job_metric_collection, "interval", seconds=60)

    # Add File Watcher (60s)
    scheduler.add_job(job_file_watcher, "interval", seconds=60)

    scheduler.start()
    print(f"⏰ Background Scheduler Started (max {settings.MAX_CONCURRENT_SERVERS} concurrent servers)")
