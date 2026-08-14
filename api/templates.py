"""
Templates API
Template management endpoints
"""
import os
import json
import time
from typing import Optional, List, Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from core.config import AppConfig
from core.dependencies import verify_session
from core.database import load_config, update_config
from helpers import handle_api_errors, generate_timestamp_id
from logger_config import get_logger
from services.config_merger import ConfigMerger, ProxyGroupGenerator
from services.node_metadata import strip_node_metadata

logger = get_logger(__name__)
router = APIRouter()

YAML_SOURCE_DIR = AppConfig.YAML_SOURCE_DIR
OUTPUT_FILE = os.path.join(AppConfig.DATA_DIR, 'myconfig.yaml')


def _split_template_content(content: str) -> tuple[str, str]:
    """Split a full YAML template while keeping rules and trailing sections intact."""
    lines = content.strip().splitlines()
    proxy_groups_index = next(
        (index for index, line in enumerate(lines) if line.strip().startswith('proxy-groups:')),
        None,
    )
    rules_index = next(
        (index for index, line in enumerate(lines) if line.strip().startswith('rules:')),
        None,
    )
    split_index = rules_index if rules_index is not None else proxy_groups_index
    if split_index is None:
        return content.strip(), ''
    return '\n'.join(lines[:split_index]).strip(), '\n'.join(lines[split_index:]).strip()


def _template_content(template: dict) -> str:
    """Render a template record without hand-built YAML indentation."""
    import yaml

    parts = []
    if template.get('header'):
        parts.append(str(template['header']).rstrip())
    groups = template.get('proxy_groups')
    if isinstance(groups, list) and groups:
        parts.append(yaml.safe_dump(
            {'proxy-groups': groups},
            allow_unicode=True,
            sort_keys=False,
        ).rstrip())
    if template.get('suffix'):
        parts.append(str(template['suffix']).strip())
    return '\n\n'.join(part for part in parts if part)


# ==================== Built-in Template ====================

def get_builtin_template():
    """Get the built-in default template"""
    proxy_groups = ProxyGroupGenerator.generate_groups([], {})
    editable_group_names = {
        '🚀 手动选择',
        '♻️ 自动选择(测速)',
        '🔯 故障转移',
    }
    for proxy_group in proxy_groups:
        proxy_group['_editable'] = proxy_group.get('name') in editable_group_names

    return {
        'id': 'builtin',
        'name': '内置模板',
        'header': ConfigMerger.DEFAULT_HEADER,
        'suffix': ConfigMerger.DEFAULT_SUFFIX,
        'proxy_groups': proxy_groups,
        'builtin': True
    }


# ==================== Data Models ====================

class CreateTemplate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    header: str = ""
    suffix: str = ""
    proxy_groups: Optional[List[dict]] = None
    content: Optional[str] = None

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value):
        normalized = value.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        return normalized


class UpdateTemplate(BaseModel):
    name: Optional[str] = Field(None, max_length=100)
    header: Optional[str] = None
    suffix: Optional[str] = None
    proxy_groups: Optional[List[dict]] = None
    content: Optional[str] = None  # Legacy format support

    @field_validator('name')
    @classmethod
    def normalize_name(cls, value):
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError('Name cannot be empty')
        return normalized


class TemplateContent(BaseModel):
    content: str
    file_aliases: Optional[Dict[str, str]] = None


# ==================== API Endpoints ====================

@router.get("")
@handle_api_errors
def list_templates(_: bool = Depends(verify_session)):
    """List all templates"""
    config = load_config()
    templates = config.get('templates', [])
    
    # Add is_builtin flag to custom templates
    for template in templates:
        if 'is_builtin' not in template:
            template['is_builtin'] = False
        if 'is_modified' not in template:
            template['is_modified'] = False
    
    # Add builtin template to the list
    builtin = get_builtin_template()
    builtin['is_builtin'] = True
    builtin['is_modified'] = 'builtin_template_override' in config
    builtin['content'] = _template_content(builtin)
    for template in templates:
        template['content'] = _template_content(template)
    
    return {"templates": [builtin] + templates}


@router.get("/builtin")
@handle_api_errors
def get_builtin_template_endpoint(_: bool = Depends(verify_session)):
    """Get built-in template"""
    config = load_config()
    template = get_builtin_template()
    
    # Apply override if exists
    override = config.get('builtin_template_override', {})
    if override:
        if 'header' in override:
            template['header'] = override['header']
        if 'suffix' in override:
            template['suffix'] = override['suffix']
        if 'proxy_groups' in override:
            template['proxy_groups'] = override['proxy_groups']
    
    template['content'] = _template_content(template)
    return {"template": template}


@router.get("/{template_id}")
@handle_api_errors
def get_template(template_id: str, _: bool = Depends(verify_session)):
    """Get template by ID"""
    config = load_config()
    
    if template_id == 'builtin':
        template = get_builtin_template()
        # Apply override if exists
        override = config.get('builtin_template_override', {})
        if override:
            if 'header' in override:
                template['header'] = override['header']
            if 'suffix' in override:
                template['suffix'] = override['suffix']
            if 'proxy_groups' in override:
                template['proxy_groups'] = override['proxy_groups']
        template['content'] = _template_content(template)
        return {"template": template}
    
    for template in config.get('templates', []):
        if template['id'] == template_id:
            result = dict(template)
            result['content'] = _template_content(result)
            return {"template": result}
    
    raise HTTPException(status_code=404, detail="Template not found")


@router.post("")
@handle_api_errors
def create_template(data: CreateTemplate, _: bool = Depends(verify_session)):
    """Create a new template"""
    header = data.header
    suffix = data.suffix
    proxy_groups = data.proxy_groups
    if data.content is not None:
        import yaml
        try:
            parsed = yaml.safe_load(data.content)
        except yaml.YAMLError as exc:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {exc}") from None
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="Template content must be a YAML object")
        proxy_groups = parsed.get('proxy-groups', proxy_groups or [])
        header, suffix = _split_template_content(data.content)

    def add_template(config: dict) -> dict:
        template_id = generate_timestamp_id('tpl_')
        template = {
            'id': template_id,
            'name': data.name,
            'header': header,
            'suffix': suffix,
            'proxy_groups': proxy_groups or [],
            'created_at': int(time.time())
        }
        config.setdefault('templates', []).append(template)
        return dict(template)

    template = update_config(add_template)
    
    return {"status": "success", "template": template}


@router.put("/{template_id}")
@handle_api_errors
def update_template(template_id: str, data: UpdateTemplate, _: bool = Depends(verify_session)):
    """Update a template"""
    # Handle legacy content format
    if data.content is not None:
        # Split content into header, proxy_groups, and suffix
        import yaml
        try:
            from yaml import CSafeLoader as YAMLLoader
        except ImportError:
            from yaml import SafeLoader as YAMLLoader
        
        try:
            parsed = yaml.load(data.content, Loader=YAMLLoader)
            if isinstance(parsed, dict):
                # Extract proxy-groups if present
                proxy_groups = parsed.get('proxy-groups', [])
                
                # Remove proxy-groups from parsed to get header
                if 'proxy-groups' in parsed:
                    del parsed['proxy-groups']
                
                # Find where rules start (this becomes suffix)
                content_lines = data.content.split('\n')
                rules_index = -1
                for i, line in enumerate(content_lines):
                    if line.strip().startswith('rules:'):
                        rules_index = i
                        break
                
                if rules_index >= 0:
                    header = '\n'.join(content_lines[:rules_index]).strip()
                    suffix = '\n'.join(content_lines[rules_index:]).strip()
                else:
                    # No rules section, treat everything before proxy-groups as header
                    pg_index = -1
                    for i, line in enumerate(content_lines):
                        if line.strip().startswith('proxy-groups:'):
                            pg_index = i
                            break
                    if pg_index >= 0:
                        header = '\n'.join(content_lines[:pg_index]).strip()
                        suffix = ''
                    else:
                        header = data.content.strip()
                        suffix = ''
                
                data.header = header
                data.suffix = suffix
                data.proxy_groups = proxy_groups
        except Exception:
            # If parsing fails, treat as plain header
            data.header = data.content
            data.suffix = ''
            data.proxy_groups = []
    
    def apply_template_update(config: dict) -> dict:
        if template_id == 'builtin':
            # Update builtin template override
            override = config.get('builtin_template_override', {})
            if data.header is not None:
                override['header'] = data.header
            if data.suffix is not None:
                override['suffix'] = data.suffix
            if data.proxy_groups is not None:
                override['proxy_groups'] = data.proxy_groups
            config['builtin_template_override'] = override
            return dict(override)

        for template in config.get('templates', []):
            if template['id'] == template_id:
                if data.name is not None:
                    template['name'] = data.name
                if data.header is not None:
                    template['header'] = data.header
                if data.suffix is not None:
                    template['suffix'] = data.suffix
                if data.proxy_groups is not None:
                    template['proxy_groups'] = data.proxy_groups
                return dict(template)

        raise HTTPException(status_code=404, detail="Template not found")

    template = update_config(apply_template_update)
    return {"status": "success", "template": template}


@router.delete("/{template_id}")
@handle_api_errors
def delete_template(template_id: str, _: bool = Depends(verify_session)):
    """Delete a template"""
    if template_id == 'builtin':
        raise HTTPException(status_code=400, detail="Cannot delete builtin template")

    def remove_template(config: dict):
        templates = config.get('templates', [])
        if not any(t.get('id') == template_id for t in templates):
            raise HTTPException(status_code=404, detail="Template not found")
        config['templates'] = [t for t in templates if t['id'] != template_id]
        for subject in [*config.get('users', []), *config.get('admin_tokens', [])]:
            if isinstance(subject, dict) and subject.get('template_id') == template_id:
                subject['template_id'] = 'builtin'

    update_config(remove_template)

    return {"status": "success"}


@router.post("/builtin/reset")
@handle_api_errors
def reset_builtin_template(_: bool = Depends(verify_session)):
    """Reset builtin template to default"""
    def reset_builtin_override(config: dict):
        # Remove builtin template override
        config.pop('builtin_template_override', None)

    update_config(reset_builtin_override)
    
    return {"status": "success", "message": "Builtin template reset to default"}


@router.post("/{template_id}/duplicate")
@handle_api_errors
def duplicate_template(template_id: str, _: bool = Depends(verify_session)):
    """Duplicate a template"""
    def duplicate_existing_template(config: dict) -> dict:
        if template_id == 'builtin':
            source = get_builtin_template()
            # Apply override if exists
            override = config.get('builtin_template_override', {})
            if override:
                if 'header' in override:
                    source['header'] = override['header']
                if 'suffix' in override:
                    source['suffix'] = override['suffix']
                if 'proxy_groups' in override:
                    source['proxy_groups'] = override['proxy_groups']
        else:
            source = next((t for t in config.get('templates', []) if t['id'] == template_id), None)
            if not source:
                raise HTTPException(status_code=404, detail="Template not found")

        new_id = generate_timestamp_id('tpl_')
        base_name = str(source.get('name', 'Template')).strip() or 'Template'
        copy_suffix = ' (Copy)'
        new_template_name = f"{base_name[:100 - len(copy_suffix)]}{copy_suffix}"
        new_template = {
            'id': new_id,
            'name': new_template_name,
            'header': source.get('header', ''),
            'suffix': source.get('suffix', ''),
            'proxy_groups': source.get('proxy_groups', []),
            'created_at': int(time.time())
        }
        config.setdefault('templates', []).append(new_template)
        return dict(new_template)

    new_template = update_config(duplicate_existing_template)
    
    return {"status": "success", "template": new_template}


@router.post("/preview")
@handle_api_errors
def preview_template(data: TemplateContent, _: bool = Depends(verify_session)):
    """Preview template merge result"""
    from services.config_merger import ConfigMerger
    
    try:
        merger = ConfigMerger(
            yaml_dir=YAML_SOURCE_DIR,
            output_file=OUTPUT_FILE,
            custom_header=data.content,
            file_aliases=data.file_aliases or {}
        )
        cfg = merger.merge_and_generate()
        proxies = cfg.get('proxies', [])
        proxy_groups = cfg.get('proxy-groups', [])

        preview_parts = [data.content.rstrip()]
        if proxies:
            preview_parts.append('\nproxies:')
            for proxy in proxies:
                preview_parts.append(
                    f'  - {json.dumps(strip_node_metadata(proxy), ensure_ascii=False, separators=(",",":"))}'
                )
        if proxy_groups:
            preview_parts.append('\nproxy-groups:')
            for group in proxy_groups:
                preview_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')

        result = "\n".join(preview_parts)
        return {"status": "success", "preview": result}
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Template preview failed: {e}") from None
