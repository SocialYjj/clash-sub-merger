"""Compatibility routes for the original single-template API."""

import json
import os
from collections import OrderedDict
from typing import Callable, Tuple

import yaml
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel

from core.dependencies import verify_session
from core.models import FinalContent, TemplateContent
from helpers import Constants
from services.config_merger import ConfigMerger

try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:  # pragma: no cover - depends on optional PyYAML C extension
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

def split_template(full_content: str) -> Tuple[str, str]:
    """
    Split template into header (config before proxies) and suffix (rules after proxy-groups).
    Removes proxies: and proxy-groups: sections completely.
    """
    lines = full_content.splitlines(keepends=True)
    header_lines, suffix_lines = [], []
    state = 0  # 0=header, 1=skip(proxies/groups), 2=suffix

    for line in lines:
        stripped = line.strip()

        if state == 0:
            # In header section
            if stripped.startswith('proxies:') or stripped.startswith('proxy-groups:'):
                # Start skipping proxies/proxy-groups sections
                state = 1
                continue
            header_lines.append(line)

        elif state == 1:
            # Skipping proxies/proxy-groups sections
            # Check if we've reached the suffix (rules, etc.)
            if any(stripped.startswith(k) for k in ['rules:', 'rule-providers:', 'script:', 'url-rewrite:']):
                state = 2
                suffix_lines.append(line)
            # Otherwise, skip this line (it's part of proxies/proxy-groups)

        elif state == 2:
            # In suffix section
            suffix_lines.append(line)

    return "".join(header_lines).strip(), "".join(suffix_lines).strip()



def create_template_router(
    *,
    yaml_source_dir: str,
    output_file: str,
    load_config: Callable[[], dict],
    update_config: Callable[[Callable[[dict], object]], object],
    logger,
) -> APIRouter:
    """Create compatibility routes for legacy single-template endpoints."""
    router = APIRouter()
    YAML_SOURCE_DIR = yaml_source_dir
    OUTPUT_FILE = output_file

    @router.get("/api/template", tags=["templates"])
    def get_saved_template(_: bool = Depends(verify_session)):
        """Get saved template or default if none saved"""
        config = load_config()
        if 'template' in config:
            template = config['template']
            header = template.get('header', ConfigMerger.DEFAULT_HEADER)
            suffix = template.get('suffix', ConfigMerger.DEFAULT_SUFFIX)
        else:
            header = ConfigMerger.DEFAULT_HEADER
            suffix = ConfigMerger.DEFAULT_SUFFIX
        return {"content": header.strip() + "\n\nproxies: []\n\nproxy-groups: []\n\n" + suffix.strip()}

    @router.get("/api/template/default", tags=["templates"])
    def get_default_template(_: bool = Depends(verify_session)):
        header = ConfigMerger.DEFAULT_HEADER
        suffix = ConfigMerger.DEFAULT_SUFFIX
        return {"content": header.strip() + "\n\nproxies: []\n\nproxy-groups: []\n\n" + suffix.strip()}

    @router.post("/api/template/parse", tags=["templates"])
    async def parse_template_file(file: UploadFile = File(...), current_template: str = Form(default=""), _: bool = Depends(verify_session)):
        """Parse uploaded template file with size validation"""
        try:
            # Read file content with size limit
            content_bytes = await file.read()

            # Validate file size
            if len(content_bytes) > Constants.MAX_REQUEST_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Maximum size: {Constants.MAX_REQUEST_SIZE / 1024 / 1024:.1f}MB"
                )

            content = content_bytes.decode('utf-8')

            try:
                uploaded_config = yaml.load(content, Loader=YAMLLoader)
            except yaml.YAMLError as e:
                raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")

            if not isinstance(uploaded_config, dict):
                raise HTTPException(status_code=400, detail="Invalid file format")

            if current_template:
                try:
                    base_config = yaml.load(current_template, Loader=YAMLLoader)
                except yaml.YAMLError as e:
                    logger.warning(f"Failed to parse current template: {e}")
                    base_config = {}
                except Exception as e:
                    logger.error(f"Error loading current template: {e}")
                    base_config = {}
            else:
                header = ConfigMerger.DEFAULT_HEADER
                suffix = ConfigMerger.DEFAULT_SUFFIX
                try:
                    base_config = yaml.load(header + "\nproxies: []\nproxy-groups: []\n" + suffix, Loader=YAMLLoader)
                except yaml.YAMLError as e:
                    logger.error(f"Failed to parse default template: {e}")
                    base_config = {}
                except Exception as e:
                    logger.error(f"Error loading default template: {e}")
                    base_config = {}

            if not isinstance(base_config, dict):
                base_config = {}

            merged = {}
            for key in base_config:
                if key == 'proxies':
                    merged[key] = []
                elif key == 'proxy-groups':
                    # Preserve from uploaded config if exists
                    continue
                elif key in uploaded_config:
                    merged[key] = uploaded_config[key]
                else:
                    merged[key] = base_config[key]

            for key in uploaded_config:
                if key not in merged:
                    if key == 'proxies':
                        merged[key] = []
                    elif key == 'proxy-groups':
                        # Process proxy-groups: keep structure, clean proxy nodes
                        pass
                    else:
                        merged[key] = uploaded_config[key]

            merged['proxies'] = []

            # Process proxy-groups: keep structure, clean proxy node names
            uploaded_groups = uploaded_config.get('proxy-groups', [])
            if uploaded_groups and isinstance(uploaded_groups, list):
                # Get all group names defined in the config
                group_names = set()
                for group in uploaded_groups:
                    if isinstance(group, dict) and group.get('name'):
                        group_names.add(group['name'])

                # Special entries to preserve
                preserved_entries = {'DIRECT', 'REJECT', 'GLOBAL', 'PASS'}
                preserved_entries.update(group_names)

                cleaned_groups = []
                for group in uploaded_groups:
                    if not isinstance(group, dict):
                        continue
                    cleaned_group = dict(group)
                    proxies = group.get('proxies', [])
                    if isinstance(proxies, list):
                        # Keep only DIRECT, REJECT, and other group references
                        cleaned_proxies = [p for p in proxies if p in preserved_entries]
                        cleaned_group['proxies'] = cleaned_proxies
                    cleaned_groups.append(cleaned_group)

                merged['proxy-groups'] = cleaned_groups
            else:
                merged['proxy-groups'] = []

            new_content = yaml.dump(merged, allow_unicode=True, sort_keys=False, default_flow_style=False, width=float("inf"), Dumper=YAMLDumper)
            section_keys = ['dns:', 'sniffer:', 'tun:', 'proxies:', 'proxy-groups:', 'rules:', 'rule-providers:', 'script:', 'url-rewrite:']
            lines = new_content.split('\n')
            result_lines = []
            for line in lines:
                stripped = line.strip()
                if any(stripped.startswith(key) for key in section_keys):
                    if not line.startswith(' ') and not line.startswith('\t'):
                        if result_lines and result_lines[-1].strip() != '':
                            result_lines.append('')
                result_lines.append(line)
            return {"content": '\n'.join(result_lines).strip()}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    class TemplateSaveRequest(BaseModel):
        content: str

    @router.post("/api/template/save", tags=["templates"])
    def save_template(data: TemplateSaveRequest, _: bool = Depends(verify_session)):
        """Save template content to config"""
        try:
            content = data.content.strip()
            # Parse to validate YAML
            try:
                parsed = yaml.load(content, Loader=YAMLLoader)
                if not isinstance(parsed, dict):
                    raise HTTPException(status_code=400, detail="Invalid template format")
            except yaml.YAMLError as e:
                raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)[:100]}")

            # Split into header and suffix
            header, suffix = split_template(content)

            # Update ConfigMerger templates
            ConfigMerger.DEFAULT_HEADER = header
            ConfigMerger.DEFAULT_SUFFIX = suffix

            # Save to config.json without overwriting concurrent config changes
            def set_template(latest_config: dict):
                latest_config['template'] = {
                    'header': header,
                    'suffix': suffix
                }

            update_config(set_template)

            return {"success": True, "message": "Template saved"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @router.post("/api/preview", tags=["templates"])
    def generate_preview(template: TemplateContent, _: bool = Depends(verify_session)):
        header, suffix = split_template(template.content)

        config = load_config()
        subs = config.get('subscriptions', [])
        custom_nodes = config.get('custom_nodes', [])

        file_aliases = OrderedDict(template.file_aliases or {})

        if custom_nodes and 'custom_nodes.yaml' not in file_aliases:
            new_aliases = OrderedDict()
            new_aliases['custom_nodes.yaml'] = 'Custom'
            new_aliases.update(file_aliases)
            file_aliases = new_aliases

        for s in subs:
            if s['enabled']:
                filename = f"{s['id']}.yaml"
                if filename not in file_aliases:
                    file_aliases[filename] = s['name']

        merger = ConfigMerger(
            yaml_dir=YAML_SOURCE_DIR, output_file=OUTPUT_FILE,
            custom_header=header, custom_suffix=suffix, file_aliases=file_aliases
        )

        try:
            cfg = merger.merge_and_generate()
            proxies = cfg.get('proxies', [])
            proxy_groups = cfg.get('proxy-groups', [])

            output_parts = [header.rstrip(), '\nproxies:']
            for proxy in proxies:
                output_parts.append(f'  - {json.dumps(proxy, ensure_ascii=False, separators=(",",":"))}')
            output_parts.append('\nproxy-groups:')
            for group in proxy_groups:
                output_parts.append(f'  - {json.dumps(group, ensure_ascii=False, separators=(",",":"))}')

            if suffix:
                output_parts.append('\n' + suffix)
            return {"content": "\n".join(output_parts)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @router.post("/api/save_content", tags=["templates"])
    def save_final_content(data: FinalContent, _: bool = Depends(verify_session)):
        target = data.save_path if data.save_path else OUTPUT_FILE
        try:
            with open(target, 'w', encoding='utf-8') as f:
                f.write(data.content)
            return {"status": "success", "output_file": target}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @router.get("/api/download_result", tags=["templates"])
    def download_result(_: bool = Depends(verify_session)):
        if os.path.exists(OUTPUT_FILE):
            return FileResponse(OUTPUT_FILE, media_type='application/yaml', filename='myconfig.yaml')
        raise HTTPException(status_code=404, detail="Config not generated yet")


    return router
