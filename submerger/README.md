# SubMerger Frontend

SubMerger 的前端部分，基于 React 19 和 Vite 构建的现代化单页应用（SPA）。

## 🛠️ 技术栈

- **核心框架**: [React 19](https://react.dev/)
- **构建工具**: [Vite](https://vitejs.dev/)
- **路由管理**: [React Router v7](https://reactrouter.com/)
- **样式方案**: [TailwindCSS](https://tailwindcss.com/)
- **图标库**: [Lucide React](https://lucide.dev/)
- **数据可视化**: [ECharts](https://echarts.apache.org/) & [Recharts](https://recharts.org/)
- **拖拽排序**: [dnd-kit](https://dndkit.com/)
- **网络请求**: [Axios](https://axios-http.com/)

## 📂 项目结构

```
submerger/
├── public/              # 静态资源
├── src/
│   ├── components/      # 可复用组件 (UI卡片, 模态框等)
│   ├── pages/           # 页面组件
│   │   ├── Dashboard.jsx   # 仪表盘
│   │   ├── Subscriptions.jsx # 订阅管理 (卡片视图)
│   │   ├── Nodes.jsx       # 节点管理
│   │   └── Settings.jsx    # 系统设置
│   ├── utils/           # 工具函数 (格式化, 验证等)
│   ├── Layout.jsx       # 主布局组件
│   ├── main.jsx         # 入口文件
│   └── App.jsx          # 根组件
└── ...配置文件
```

## 🚀 开发指南

### 环境要求

- Node.js 18+
- npm 或 yarn

### 快速开始

1. **安装依赖**

   ```bash
   cd submerger
   npm install
   ```

2. **启动开发服务器**

   ```bash
   npm run dev
   ```

   开发服务器通常运行在 `http://localhost:5173`。请确保后端 API 服务器已在 `http://localhost:8666` 运行，Vite 已配置代理转发 `/api` 请求。

3. **构建生产版本**

   ```bash
   npm run build
   ```

   构建产物将输出到 `dist/` 目录。后端服务器会自动托管此目录下的静态文件。

## 🎨 UI/UX 特性

- **现代化卡片设计**: 订阅管理采用圆角卡片布局，视觉效果佳。
- **智能配色**: 根据订阅/节点名称自动生成不同的主题色（Avatar, 标签等）。
- **暗色模式**: 默认深色主题，适配极客风格。
- **响应式布局**: 完美适配移动端和桌面端。
- **交互动画**: 使用 CSS Transitions 和 Framer Motion 实现流畅的交互反馈。

## 🧩 主要组件说明

### SubscriptionCard

位于 `src/components/SubscriptionCard.jsx`。
负责展示单个订阅源的信息，包括：
- 智能生成的彩色头像
- 节点数量与定时规则标签
- 流量使用进度条（支持颜色分级：绿/黄/红）
- 快捷操作按钮组（复制、刷新、定时、编辑、删除）

### Nodes Table

位于 `src/pages/Nodes.jsx`。
提供强大的节点筛选与操作功能：
- **延迟测试**: 支持批量 TCP 延迟检测。
- **GeoIP 检测**: 自动识别节点物理位置。
- **多维度筛选**: 按协议、国家、来源筛选。

## 🤝 贡献代码

欢迎提交 PR！请确保代码风格与现有代码保持一致（使用 ESLint/Prettier 推荐规则）。
