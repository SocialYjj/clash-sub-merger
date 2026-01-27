# Contributing to Clash Sub Merger

感谢你对本项目的关注！欢迎提交 Issue 和 Pull Request。

## 开发环境设置

### 前置要求

- Python 3.12+
- Node.js 20+
- Go 1.22+ (用于 speedtest 服务)
- Docker (可选，用于容器化部署)

### 本地开发

1. 克隆仓库
```bash
git clone https://github.com/SocialYjj/clash-sub-merger.git
cd clash-sub-merger
```

2. 安装 Python 依赖
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

3. 安装前端依赖
```bash
cd submerger
npm install
```

4. 编译 Go speedtest 服务
```bash
cd speedtest
go build -o speedtest .
```

5. 启动开发服务器
```bash
# 终端 1: 后端
python server.py

# 终端 2: 前端 (开发模式)
cd submerger
npm run dev
```

### 使用 Pre-commit Hooks

```bash
pip install pre-commit
pre-commit install
```

## 代码规范

### Python
- 使用 Black 格式化代码
- 使用 isort 排序 import
- 遵循 PEP 8 规范
- 最大行长度 120 字符

### JavaScript/React
- 使用 ESLint + Prettier
- 使用函数组件和 Hooks
- 组件文件使用 .jsx 扩展名

### Git Commit 规范

提交信息格式：
```
<type>(<scope>): <subject>

<body>
```

Type 类型：
- `feat`: 新功能
- `fix`: Bug 修复
- `docs`: 文档更新
- `style`: 代码格式 (不影响功能)
- `refactor`: 重构
- `perf`: 性能优化
- `test`: 测试相关
- `chore`: 构建/工具相关

示例：
```
feat(subscription): add batch refresh with concurrency limit

- Add semaphore to limit concurrent requests
- Prevent rate limiting from upstream servers
```

## 提交 Pull Request

1. Fork 本仓库
2. 创建功能分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'feat: add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建 Pull Request

### PR 检查清单

- [ ] 代码通过 lint 检查
- [ ] 添加了必要的测试
- [ ] 更新了相关文档
- [ ] 更新了 CHANGELOG.md (如果是新功能或重要修复)

## 报告 Bug

请使用 GitHub Issues，并包含以下信息：

- 问题描述
- 复现步骤
- 期望行为
- 实际行为
- 环境信息 (OS, Python 版本, 浏览器等)
- 相关日志或截图

## 功能建议

欢迎提交功能建议！请在 Issue 中描述：

- 功能描述
- 使用场景
- 可能的实现方案 (可选)

## 许可证

提交代码即表示你同意将代码以 MIT 许可证发布。
