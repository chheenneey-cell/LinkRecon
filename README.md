# 🔗 LinkRecon

<p align="center">
  <img src="assets/branding/linkrecon-logo.png" alt="LinkRecon" width="320">
</p>

用于网站安全巡检的暗链扫描工具，支持网页、本地 HTML 文件和目录，提供 Web 控制台与命令行入口。

## ✨ 功能

- 🔍 分析 HTML、JavaScript、CSS，发现隐藏链接、可疑跳转与关键词线索。
- 🌐 支持浏览器 / 百度爬虫 UA 对照，可选 Chrome 动态渲染。
- 🗂️ 支持批量扫描、任务管理、客户关联和扫描历史。
- 📄 生成 HTML、TXT、JSON、CSV 报告，保留上下文与待复核说明。

## 🚀 快速开始

在项目目录中执行：

```bash
python -m pip install -r requirements.txt
python app.py
```

浏览器访问 [http://127.0.0.1:5000/](http://127.0.0.1:5000/)。
账号库为空时，首次启动会创建 `admin` 并在终端显示随机初始口令，请登录后修改。

## 🛠️ 命令行

```bash
# 网页扫描
python LinkRecon.py https://example.com -m deep -f html

# 本地目录扫描
python LinkRecon.py ./site -m standard -f json

# 批量扫描：targets.txt 每行一个 URL 或本地路径
python LinkRecon.py --target-file targets.txt -f html

# 查看全部参数
python LinkRecon.py --help
```

扫描模式：`fast` / `standard` / `deep`；报告默认保存到 `reports/`。
启用 JS 渲染需要 Chrome 与匹配的 ChromeDriver，可使用 `--headless` 开启。

## ⚙️ 配置与数据

- 自定义词库：`--keyword-file keywords.txt`，CSV 格式为 `关键词,类别,权重`。
- Web 数据 / 报告目录：`LINKRECON_DATA_DIR` / `LINKRECON_REPORTS_DIR`。
- Web 本地扫描范围：`LINKRECON_SCAN_ROOTS`，默认仅允许项目目录。
- HTTPS 部署：设置 `LINKRECON_COOKIE_SECURE=1`。

账号、客户资料及扫描历史位于 `data/`。请保留 `.gitignore`，不要提交运行数据、口令、报告和日志。

## ⚖️ 免责声明

- 仅用于自有或明确授权目标的安全检测、研究与学习，禁止未经授权或违法使用。
- 检测结果仅是排查线索，可能存在误报、漏报，需结合上下文人工复核，不构成安全保证。
- 请求失败或扫描不完整不代表目标安全；使用者应自行评估操作风险和后续处置。
- 报告可能包含目标地址及页面内容，请妥善控制访问权限，勿公开敏感信息。

默认词库包含 Libra 来源关键词；第三方依赖及数据的使用、再分发需核对并遵守相应许可。
