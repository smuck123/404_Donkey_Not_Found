import uuid
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field


router = APIRouter(prefix="/drafts", tags=["drafts"])


class ItemDraft(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    key: str = Field(min_length=1, max_length=2048)
    value_type: str = "UNSIGNED"
    delay: str = "1m"
    units: str = ""


class TemplateDraftRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    group: str = "Templates/Custom"
    description: str = "Generated draft. Review before importing."
    items: list[ItemDraft] = Field(default_factory=list, max_length=100)


class WidgetDraft(BaseModel):
    type: str = Field(min_length=1, max_length=64)
    name: str = ""
    x: int = Field(0, ge=0, le=71)
    y: int = Field(0, ge=0, le=63)
    width: int = Field(24, ge=1, le=72)
    height: int = Field(5, ge=1, le=64)
    fields: list[dict[str, Any]] = Field(default_factory=list, max_length=100)


class DashboardDraftRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    page_name: str = "Overview"
    widgets: list[WidgetDraft] = Field(default_factory=list, max_length=100)


def new_uuid() -> str:
    return uuid.uuid4().hex


@router.post("/template", operation_id="draft_zabbix_template")
async def draft_template(request: TemplateDraftRequest) -> dict[str, Any]:
    items = []
    for item in request.items:
        row = item.model_dump()
        row["uuid"] = new_uuid()
        items.append(row)
    return {
        "draft_only": True,
        "warning": "Review and import manually. This service did not modify Zabbix.",
        "format": "json",
        "document": {
            "zabbix_export": {
                "version": "8.0",
                "template_groups": [{"uuid": new_uuid(), "name": request.group}],
                "templates": [{
                    "uuid": new_uuid(),
                    "template": request.name,
                    "name": request.name,
                    "description": request.description,
                    "groups": [{"name": request.group}],
                    "items": items,
                }],
            }
        },
    }


@router.post("/dashboard", operation_id="draft_zabbix_dashboard")
async def draft_dashboard(request: DashboardDraftRequest) -> dict[str, Any]:
    return {
        "draft_only": True,
        "warning": "Widget fields vary by type. Validate in Zabbix before importing.",
        "format": "json",
        "document": {
            "zabbix_export": {
                "version": "8.0",
                "dashboards": [{
                    "uuid": new_uuid(),
                    "name": request.name,
                    "pages": [{
                        "name": request.page_name,
                        "widgets": [widget.model_dump(exclude_defaults=True) for widget in request.widgets],
                    }],
                }],
            }
        },
    }

