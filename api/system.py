"""
System API
System management, backup, import/export, logging endpoints
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel

from core.config import AppConfig
from core.dependencies import verify_session
from services.backup import (
    create_backup as backup_create,
    list_backups as backup_list,
    restore_backup as backup_restore,
    delete_backup as backup_delete,
    export_config as config_export,
    import_config as config_import
)
from services.key_rotation import check_key_rotation_needed
from logger_config import get_logger, set_log_level, get_current_log_level, list_all_loggers

logger = get_logger(__name__)
router = APIRouter()


# ==================== Data Models ====================

class LogLevelRequest(BaseModel):
    level: str  # DEBUG, INFO, WARNING, ERROR, CRITICAL


class ImportRequest(BaseModel):
    data: dict
    merge: bool = False


# ==================== Logging API ====================

@router.get("/log-level", tags=["system"])
def get_log_level(_: bool = Depends(verify_session)):
    """Get current log level"""
    return {
        "current_level": get_current_log_level(),
        "available_levels": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        "loggers": list_all_loggers()
    }


@router.post("/log-level", tags=["system"])
def update_log_level(data: LogLevelRequest, _: bool = Depends(verify_session)):
    """Dynamically adjust log level at runtime"""
    try:
        set_log_level(data.level)
        return {
            "status": "success",
            "message": f"Log level changed to {data.level}",
            "current_level": get_current_log_level()
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/loggers", tags=["system"])
def list_loggers(_: bool = Depends(verify_session)):
    """List all registered loggers and their levels"""
    loggers = list_all_loggers()
    return {
        "loggers": loggers,
        "count": len(loggers)
    }


# ==================== Backup API ====================

@router.get("/backups", tags=["system"])
def list_backups(_: bool = Depends(verify_session)):
    """List all available backups"""
    backups = backup_list()
    return {"backups": backups, "count": len(backups)}


@router.post("/backups", tags=["system"])
def create_manual_backup(_: bool = Depends(verify_session)):
    """Create a manual backup"""
    filename = backup_create('manual')
    if filename:
        return {"status": "success", "filename": filename}
    raise HTTPException(status_code=500, detail="Failed to create backup")


@router.post("/backups/{filename}/restore", tags=["system"])
def restore_from_backup(filename: str, _: bool = Depends(verify_session)):
    """Restore from a backup"""
    try:
        backup_restore(filename)
        return {"status": "success", "message": f"Restored from {filename}"}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Backup not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to restore backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/backups/{filename}", tags=["system"])
def delete_backup_file(filename: str, _: bool = Depends(verify_session)):
    """Delete a backup"""
    try:
        backup_delete(filename)
        return {"status": "success"}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Backup not found")
    except Exception as e:
        logger.error(f"Failed to delete backup: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Import/Export API ====================

@router.get("/export", tags=["system"])
def export_configuration(_: bool = Depends(verify_session)):
    """Export full configuration for migration"""
    import time
    try:
        export_data = config_export()
        return Response(
            content=json.dumps(export_data, ensure_ascii=False, indent=2),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="submerger_export_{int(time.time())}.json"'
            }
        )
    except Exception as e:
        logger.error(f"Failed to export config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/import", tags=["system"])
def import_configuration(req: ImportRequest, _: bool = Depends(verify_session)):
    """Import configuration from export file"""
    try:
        mode = config_import(req.data, req.merge)
        return {"status": "success", "mode": mode}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to import config: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Key Rotation API ====================

@router.get("/key-rotation", tags=["system"])
def get_key_rotation_status(_: bool = Depends(verify_session)):
    """Get API key rotation status and recommendations"""
    result = check_key_rotation_needed()
    return {
        "rotation_threshold_days": AppConfig.KEY_ROTATION_DAYS,
        "keys_needing_rotation": result,
        "count": len(result),
        "check_enabled": AppConfig.KEY_ROTATION_CHECK_ENABLED
    }
