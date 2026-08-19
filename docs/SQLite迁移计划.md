# SQLite 数据迁移计划

## 目标

将当前 `data/` 中的业务配置、节点测试元数据和查询缓存迁移到 SQLite，使数据库成为应用持久化数据的唯一来源；原始订阅文件、备份文件、日志和运行锁继续保留在文件系统。

## 阶段进度

### 阶段一：数据备份与现状盘点

- 状态：已完成
- 目标：在停止本地服务后完整复制 `data/`，记录文件清单、大小和校验信息。
- 关键决策：备份目录放在仓库外，不纳入 Git；迁移期间保留原始数据，不做删除。
- 已完成：备份目录为 `G:\clash-sub-merger-backups\data_pre_sqlite_20260819_210601`，包含 78 个文件及 `BACKUP_MANIFEST.json`。
- 必需笔记：后续本地启动产生的日志和运行锁不再用于证明迁移前快照未变化；回滚以该备份目录为准。

### 阶段二：SQLite 存储层与迁移脚本

- 状态：已完成
- 目标：建立 SQLite 数据库、事务和迁移版本表，将配置、历史和缓存导入数据库。
- 关键决策：业务配置使用 SQLite 文档表保存；协议特有字段继续使用 JSON；缓存使用独立命名空间表和时间字段。
- 已完成：新增 `core/sqlite_storage.py`，启用 WAL、外键、忙等待和 `schema_migrations`；新增 `scripts/migrate_data_to_sqlite.py`。
- 迁移结果：`data/app.db` 已创建，配置集合数量为订阅 8、自建节点 30、用户 3、模板 3、管理员 Token 1、代理链 1；GeoIP 644、Radar 11、地区历史 2297 条缓存已导入。
- 设计说明：配置和每个缓存命名空间以 JSON 文档存入 SQLite，保留运行时字典契约，避免无关业务模块改写。

### 阶段三：应用读写切换

- 状态：已完成
- 目标：改造配置数据库、GeoIP、节点历史、翻译缓存、备份导入导出和启动初始化逻辑，使应用默认从 SQLite 读取和写入。
- 关键决策：保留现有模块对字典配置的调用契约，在持久化边界完成数据库与运行时对象的转换，避免无关模块大范围重写。
- 已完成：`core/database.py`、GeoIP、Cloudflare Radar、翻译、地区历史、备份导入导出和 `ddns_sync.py` 已切换到 SQLite；显式测试覆盖仍支持旧 JSON 文件路径。
- 文件系统边界：`uploads/`、`backups/`、`logs/`、刷新锁和临时事务文件继续保留在文件系统。

### 阶段四：验证与回滚检查

- 状态：已完成
- 目标：执行迁移前后数量校验、完整测试、前端构建、启动健康检查和关键 API 验证。
- 回滚条件：任一核心集合数量、订阅内容、用户、节点、缓存或备份恢复结果不一致时，停止切换并使用阶段一备份恢复。
- 已验证：Python `387 passed, 142 subtests passed`；前端 `27 passed`；前端生产构建成功；使用 `DATA_DIR=G:\clash-sub-merger\data` 启动服务后 `/health` 返回 HTTP 200，版本 `5.1.0`。
- 限制：当前 Windows 环境未安装 Docker CLI，未执行 Docker 镜像构建；Dockerfile 的静态检查不能替代真实镜像构建结果。

### 阶段五：收尾

- 状态：已完成
- 目标：确认 SQLite 数据库文件权限、Docker 挂载、备份策略和升级说明；迁移成功后再决定是否删除旧 JSON 文件。
- 当前约束：本阶段不删除原始 `data/` 文件，不删除旧 `config.json`，待验收通过后再单独处理。
- 已完成：SQLite 文件权限按 `0600` 写入；旧 JSON、旧缓存和阶段一备份均保留作为回滚来源；`README.md` 与 `README_CN.md` 已说明新的存储边界。
- 后续注意事项：部署时必须继续挂载整个 `data/` 目录；升级后首次启动会从旧 JSON 自动补齐缺失的 SQLite 文档，但不会覆盖已经存在的数据库文档。

## 数据归属

| 数据 | 迁移到 SQLite | 继续使用文件系统 |
|---|---:|---:|
| `config.json` 中的用户、订阅、自建节点、模板、代理链、设置、Token | 是 | 否 |
| 节点地区历史、测速结果、GeoIP/Radar/翻译缓存 | 是 | 否 |
| `uploads/` 原始订阅文件 | 否 | 是 |
| `backups/` 备份文件 | 否 | 是 |
| `logs/` 日志 | 否 | 是 |
| 锁文件、临时事务目录、版本缓存 | 否 | 是 |

## 必须完成的验收

- 迁移前后配置集合和关键字段数量一致。
- 订阅刷新、节点管理、节点测试、GeoIP、Radar、翻译配置、导入导出和备份恢复可用。
- SQLite 使用事务和 WAL；敏感字段仍按最小暴露原则保存，并限制数据库文件权限。
- Python 测试、前端测试、生产构建和本地健康检查全部通过。

## 阶段六：PostgreSQL 与 MySQL 对等迁移测试

- 状态：已完成
- 目标：在 WSL2 中安装数据库服务，为项目提供可切换的 PostgreSQL/MySQL 文档存储后端，并用当前 SQLite 快照验证迁移结果。
- 环境：Ubuntu 24.04（WSL2）、PostgreSQL 18.6、MySQL 9.7.2；两个服务均已启用并运行。
- 已完成：新增 `core/storage.py`、`core/postgresql_storage.py`、`core/mysql_storage.py`；配置、GeoIP、Radar、翻译、地区历史和备份相关模块统一通过存储门面访问。
- 迁移脚本：`scripts/migrate_data_to_database.py` 从 `data/app.db` 读取文档和缓存，分别写入 PostgreSQL `clash_sub_merger_pg` 与 MySQL `clash_sub_merger_mysql`，源/目标 JSON 载荷 SHA-256 均为 `26c2486bd1c8804398567d8df56ac8911badb21924372784fc05174cd6a424d1`，缓存过期时间也已保留。
- 数量校验：两套数据库均为 `app_documents=1`、`cache_documents=3`，与 SQLite 一致；配置集合为订阅 8、自建节点 30、用户 3、模板 3、管理员 Token 1、代理链 1。
- 对等测试：PostgreSQL、MySQL 的配置/缓存读写、Unicode 载荷、删除缓存和应用层 `load_config()` 均通过；分别以 8667、8668 端口启动服务后 `/health` 返回 HTTP 200（MySQL 首次启动等待服务就绪后通过）。
- 保留策略：SQLite `data/app.db`、迁移前备份和旧 JSON 文件均未删除；PostgreSQL/MySQL 测试数据库为独立实例，不覆盖现有 SQLite 运行数据。
- 运行约束：Windows 访问 WSL MySQL 时若 `127.0.0.1:3306` 未转发，应使用当前 WSL IP；在 WSL/VPS 内运行则使用 `127.0.0.1`。WSL 重启后 IP 可能变化，不应把该临时地址写入生产配置。
