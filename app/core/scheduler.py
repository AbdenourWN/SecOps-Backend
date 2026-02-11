from apscheduler.schedulers.asyncio import AsyncIOScheduler
from app.modules.servers.service import ServerService
from app.modules.logs.service import LogService
from app.modules.metrics.service import MetricService 
from app.core.database import get_database

scheduler = AsyncIOScheduler()

async def job_health_check():
    """Runs every 30 seconds"""
    # We instantiate the service here to ensure a fresh state
    try:
        service = ServerService()
        await service.update_all_server_statuses()
    except Exception as e:
        print(f"❌ Health Check Failed: {e}")

async def job_log_collection():
    """Runs every 60 seconds"""
    try:
        db = get_database()
        service = LogService()
        
        # Fetch all servers
        servers = await db["servers"].find().to_list(length=1000)
        
        print(f"📥 Running Auto-Log Collection for {len(servers)} servers...")
        for server in servers:
            # In Phase 4, we will parallelize this
            await service.collect_logs_from_server(str(server["_id"]))
            
    except Exception as e:
        print(f"❌ Log Collection Failed: {e}")

async def job_metric_collection():
    """Runs every 60 seconds"""
    try:
        db = get_database()
        service = MetricService()
        servers = await db["servers"].find().to_list(length=1000)
        
        # print(f"📊 Collecting Metrics for {len(servers)} servers...")
        for server in servers:
            await service.collect_metrics(str(server["_id"]))
    except Exception as e:
        print(f"❌ Metric Collection Failed: {e}")


def start_scheduler():
    # Add Health Check (30s)
    scheduler.add_job(job_health_check, 'interval', seconds=30)
    
    # Add Log Collection (60s)
    scheduler.add_job(job_log_collection, 'interval', seconds=60)

    # Add Metric Collection (60s)
    scheduler.add_job(job_metric_collection, 'interval', seconds=60)

    
    scheduler.start()
    print("⏰ Background Scheduler Started")