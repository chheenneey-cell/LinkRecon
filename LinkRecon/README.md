# LinkRecon - 专业暗链扫描工具

LinkRecon 是一款功能强大的专业暗链扫描工具，专注于检测网站、HTML文件或目录中的隐蔽链接、隐藏元素和恶意代码。该工具能够智能识别扫描目标类型（本地文件/目录、内网URL、公网URL），并自动调整扫描策略以获得最佳效果，是安全人员进行网站安全审计和应急响应的理想工具。

## 功能特性

### 智能目标识别与处理
- **多类型目标支持**：自动识别和扫描本地文件、本地目录、内网URL和公网URL
- **差异化扫描策略**：根据目标类型应用最优扫描策略
- **递归目录扫描**：支持可配置的扫描深度
- **文件过滤机制**：支持通过通配符排除特定文件或目录

### 核心扫描能力
- **多层次检测机制**：HTML代码检测、JavaScript代码分析、CSS代码检测、元标签扫描、注释内容分析
- **高级威胁识别**：加密/编码链接检测、可疑域名检测、随机生成域名检测、短链接服务检测、非标准端口检测、可疑查询参数检测
- **特殊隐藏手法检测**：CSS隐藏技术、颜色隐藏、零宽字符隐藏、字体大小隐藏等
- **关键字匹配系统**：支持CSV格式自定义关键字文件，包含关键字、类别和风险权重
- **智能风险评分**：基于多维度风险评估

### 无头浏览器增强检测
- **动态内容捕获**：使用Chrome无头浏览器执行JavaScript并捕获动态内容
- **DOM操作监控**：跟踪动态DOM修改
- **iframe深度分析**：渲染和分析iframe内容
- **网络请求捕获**：监控HTTP请求和重定向链

### 全面的报告系统
- **多种报告格式**：文本报告(txt)、HTML报告(html)、JSON报告(json)、CSV报告(csv)
- **丰富的报告内容**：扫描概览、问题详情、风险评估、上下文展示
- **来源类型标注**：在可疑链接中增加 `context_type` 字段（如 `html/js/css/comments`），用于区分链接的来源场景，便于后续数据分析与过滤
 - **来源标签与位置**：统一输出 `source_tag`（如 `debug/normal`）与定位范围 `position (start,end)`，HTML/CSV/JSON 报告保持一致
 - **风险排序与阈值展示**：HTML报告对“可疑链接”按风险降序展示，并默认仅展示风险≥4的项，减少噪音；关键字匹配表支持从上下文提取可点击链接

### 灵活的配置选项

- **UA 双视角**：URL 扫描默认分别使用普通浏览器和百度爬虫 UA；响应相同只检测一次，不同响应分别检测并标注来源。在“引擎配置 → 请求 UA 策略”可切换为单视角。双视角通常增加一次请求，不随机轮换 UA、不伪造搜索来源 Referer；模拟 UA 不具有搜索爬虫 IP 身份。
- **UA 差异报告**：HTML/TXT/CSV 显示身份、状态码、最终地址及独有链接/关键词；JSON 保留完整对照数据。差异不是恶意结论，单侧失败明确标为对照不完整。
- **词库来源**：已合并 Libra 的去重关键词，审查清理后默认库共 2868 条；现有分类/权重不被导入词覆盖，新增规则使用中性权重 5。常见业务歧义词需要独立、同类别、非弱且权重至少 7 的附近关键词佐证，否则保留为待复核，不单独计入高危。

```bash
python LinkRecon.py https://example.com --ua-mode dual -f html
python LinkRecon.py https://example.com --ua-mode browser --user-agent "CustomBrowser/1.0"
```

- **多种扫描模式**：fast/standard/deep
- **性能优化选项**：可配置并发线程数、请求超时设置、代理服务器支持
 - **关键词来源**：支持从 `keywords_example.txt` 或自定义 `--keyword-file` 读取，文件允许 `#` 注释行，CSV格式：`关键字,类别,风险权重`

## 安装指南

### 环境要求
- Python 3.8+

### 安装依赖
```bash
pip install -r requirements.txt
```

## 使用方法

### 启动 Web 控制台

在项目目录执行：

```bash
python app.py
```

浏览器访问 `http://127.0.0.1:5000/`。首次启动、且没有任何账号时，
程序会创建 `admin` 管理员并在启动终端显示随机初始口令；请登录后修改口令。
账号管理命令可通过 `python -m core.auth --help` 查看。没有固定默认密码。

本源码包不包含原环境的账号、会话密钥、客户资料、扫描历史、报告或日志。
运行后产生的 `data/`、`reports/` 和日志由 `.gitignore` 排除，不应上传到 Git。
`.gitignore` 是防止误提交运行数据的配置文件，不包含 Git 历史。

### 部署环境变量

命令行入口为 `LinkRecon.py`，控制台文件为 `linkrecon_console.html`。
部署脚本使用 `LINKRECON_DATA_DIR`、`LINKRECON_REPORTS_DIR` 指定运行数据和报告目录，
使用 `LINKRECON_SCAN_ROOTS` 指定本地扫描允许的根目录（多个路径以系统路径分隔符分开），
HTTPS 部署使用 `LINKRECON_COOKIE_SECURE=1` 启用安全 Cookie。
不再读取其他品牌前缀的变量；未设置时仍使用项目内的默认目录，不重置已有账号或会话密钥。

### 查看帮助信息
```bash
python LinkRecon.py --help
```

### 完整使用案例命令

#### 1. 本地文件扫描场景
```bash
# 基本扫描 - 单个HTML文件
python LinkRecon.py /path/to/file.html

# 高级扫描 + HTML报告
python LinkRecon.py /path/to/file.html -m standard -f html

# 详细日志模式
python LinkRecon.py /path/to/suspicious.html --verbose

# 自定义输出目录
python LinkRecon.py /path/to/file.html -o /custom/report/dir

# 特定报告格式（JSON）
python LinkRecon.py /path/to/file.html -f json
```

#### 2. 本地目录扫描场景
```bash
# 默认深度扫描目录
python LinkRecon.py /path/to/website

# 自定义深度扫描（仅当前目录和一级子目录）
python LinkRecon.py /path/to/website -d 1

# 深度递归扫描
python LinkRecon.py /path/to/website -d 5

# 排除特定文件/目录
python LinkRecon.py /path/to/website --exclude "*.jpg" "*.png" "logs/*" "vendor/"

# 调整线程数（提高性能）
python LinkRecon.py /path/to/website -t 16

# 完整模式 + 多格式报告
python LinkRecon.py /path/to/website -m deep -f html -o security_reports --threads 12
```

#### 3. 网络URL扫描场景
```bash
# 基本网站扫描
python LinkRecon.py https://example.com

# 内网地址扫描
python LinkRecon.py http://192.168.1.100

# 本地开发服务器扫描
python LinkRecon.py http://localhost:8080

# 带路径的URL扫描
python LinkRecon.py https://example.com/news/article

# 设置超时时间（公网默认使用全局超时，内网未显式设置时会按较长超时）
python LinkRecon.py https://example.com --timeout 60

# 使用代理服务器
python LinkRecon.py https://example.com --proxy http://127.0.0.1:8080

# 带认证的代理
python LinkRecon.py https://example.com --proxy http://username:password@proxy.example.com:8080
```

#### 4. 高级功能场景
```bash
# 无头浏览器扫描（动态内容）
python LinkRecon.py https://dynamic-website.com --headless

# 无头浏览器 + 延长等待时间
python LinkRecon.py https://heavy-js-website.com --headless --js-wait 10

# 无头浏览器超时时间
python LinkRecon.py https://example.com --headless --headless-timeout 120

# 自定义关键字检测
python LinkRecon.py /path/to/target --keyword-file custom_keywords.txt

# 基础模式快速扫描
python LinkRecon.py https://example.com -m fast -d 1 -t 5

# 全部模式深度扫描
python LinkRecon.py /path/to/important-site -m deep -d 3 -f html --verbose
```

#### 5. 批量目标扫描（多链接/多路径）
```bash
# 方式A：指定列表文件（每行一个目标：URL/文件/目录）
python LinkRecon.py --target-file e:\targets.txt -m deep -f html -o reports --verbose

# 方式B：直接把 .txt 作为 target 传入（同样按列表处理）
python LinkRecon.py e:\targets.txt -m deep -f html -o reports --verbose

# 示例列表文件内容
# https://example.com
# e:\webroot
# e:\webroot\index.html
```

#### 6. 特定场景优化命令
```bash
# 应急响应场景
python LinkRecon.py /compromised/webroot -m deep -f html -o incident_response --keyword-file malware_keywords.txt --verbose

# 定期安全审计
python LinkRecon.py /path/to/webroot -d 3 -m standard -f json -o weekly_scan_$(date +%Y%m%d)

# 新闻页面专项扫描
python LinkRecon.py https://example.com/news -m deep -d 1 -t 8 --verbose

# 大规模并行扫描
python LinkRecon.py /large/website -d 2 -t 20 --exclude "*.zip" "*.rar" "backup/*"

# 自动化集成扫描（生成JSON报告）
python LinkRecon.py https://example.com -f json -o automated_scan_results --no-color
```
### 自定义关键字文件格式
```
关键字文件为CSV格式，每行包含三个字段：

关键字,类别,风险权重
poker,gambling,8
casino,gambling,9
malware,malware,10
phishing,phishing,9
```

类别可选值：gambling (博彩)、porn (色情)、malware (恶意软件)、phishing (钓鱼)、other (其他)
风险权重范围：1-10（10为最高风险）
 默认关键字文件：项目根目录 `keywords_example.txt`（若未指定 `--keyword-file` 将自动加载）。文件允许以 `#` 开头的注释行。

## 主要参数说明

### 基本参数
- `target`: 扫描目标（文件路径、目录路径或URL）- 必需参数
- `-d, --depth`: 递归扫描深度（默认：3，0表示仅扫描当前文件/目录）
- `-m, --mode`: 扫描模式（fast/standard/deep，默认：deep）
- `-t, --threads`: 并发线程数（默认：8）

### 报告相关参数
- `-o, --output`: 报告输出目录（默认：./reports）
- `-f, --format`: 报告格式（txt/html/json/csv，默认：txt）

### 网络相关参数
- `--timeout`: 请求超时时间（秒，默认：30）。公网目标默认使用此值，内网目标未显式设置 `internal_timeout` 时按较长超时（约为全局超时的两倍）。
- `--proxy`: 代理设置（支持带认证与不带认证的HTTP代理），示例：`http://127.0.0.1:8080` 或 `http://user:pass@host:8080`

### 高级参数
- `--keyword-file`: 自定义关键字文件路径
- `--target-file`: 批量目标列表文件路径（每行一个目标：URL/文件/目录）
- `--exclude`: 排除的文件或目录
- `--verbose`: 显示详细日志信息
- `--no-color`: 禁用彩色输出（适用于自动化脚本）

### 无头浏览器参数
- `--headless`: 启用无头浏览器扫描
- `--browser-type`: 无头浏览器类型（支持: chrome，默认: chrome）
- `--js-wait`: JavaScript执行等待时间（秒，默认: 3）
- `--headless-timeout`: 无头浏览器超时时间（秒，默认: 60）
 - `--headless-binary`: Chrome二进制路径（例如：`C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe`）
 - `--headless-driver`: ChromeDriver路径（例如：`C:\\drivers\\chromedriver.exe`）

## 常见问题解答

**Q: 扫描结果中的误报如何处理？**
A: 可通过以下方式降低噪音：
- 使用自定义关键字文件调整权重
- 利用报告的风险阈值（HTML默认展示风险≥4）聚焦高风险项
- 依赖优化后的CSS检测逻辑与可信CDN白名单，避免将正常资源识别为可疑

**Q: 如何提高大型网站的扫描效率？**
A: 增加线程数、设置合理的爬取深度，或先使用基础模式（`fast`）进行初步筛选。对于公网网站，建议控制扫描范围。

**Q: 为什么有些动态生成的链接没被检测到？**
A: 启用无头浏览器模式`--headless`并适当增加JavaScript执行等待时间`--js-wait`。

**Q: 使用无头浏览器时需要注意什么？**
A: 使用无头浏览器会增加资源消耗和时间，建议适当降低线程数，为复杂页面增加等待时间，仅在必要时启用。

## 项目结构

```
LinkRecon/
├── app.py                # Flask Web 控制台入口
├── LinkRecon.py           # 主程序入口
├── gui.py                # 桌面界面入口（需额外安装 customtkinter）
├── web.py                # Streamlit 界面入口（需额外安装 streamlit）
├── linkrecon_console.html # 控制台界面
├── code.html             # 备用界面
├── templates/            # 登录模板
├── assets/               # 界面资源
├── requirements.txt      # 依赖列表
├── README.md             # 项目说明
├── .gitignore            # 排除账号、报告及本机运行文件
├── core/                 # 核心模块
│   ├── scanner.py        # 扫描引擎
│   ├── detector/         # 各类检测器
│   ├── reporter.py       # 报告生成器
│   └── config.py         # 配置管理
├── utils/                # 工具类
└── keywords_example.txt  # 关键字示例文件
```

## 许可证与免责声明

本工具仅供安全测试和应急响应使用，请确保您有足够的授权对目标进行扫描，避免对未经授权的系统进行测试。

## 开发者提示（工具接口）
- CSS工具正式接口：`extract_css_properties/remove_css_comments/extract_css_comments`
- 统一正式接口（`extract_css_properties/remove_css_comments/extract_css_comments`）。

## 开发者选项（日志与报告）

### 关键词判定口径

- 按正文、描述属性、元信息、链接、注释及代码字符串分别匹配，不扫描标签名、class/id、代码变量名等结构字段。隐藏文本仍检测。
- 字面数字和英文规则采用标识符边界；数字正则及正则中的纯数字分支也检查边界。URL 中的数字路径、端口、参数不作为敏感类别证据。其他显式正则保留规则语义，但不能跨独立字段匹配。
- 数字（含数字正则）、单字、1～2 个字母的缩写，以及成人、视频、直播、独立、机场、存取款和医学解剖词等常见歧义词属于低信息量词。没有同一字段内、80 字符范围内、不重叠、原始权重至少 7 的同类别非弱词佐证时，保留为 `needs_review`（待复核），评估 `weight` 不超过 3，原始规则权重保存在 `rule_weight`。中性权重 5 的导入词不能把弱词抬为高危。
- 可通过 `Config.keyword_ambiguous_terms` 将业务中的歧义词补充为低信息量词（默认空列表）。佐证只能提高候选风险，不代表自动确认违规。
- HTML 实体和 URL 百分号编码解码后匹配；`match_position` / `match_end` 仍对应原始源码，报告展示判定依据。待复核项单独标识，不计入控制台的高中危统计。历史报告不会自动重算，需要重新扫描生成新报告。

- `debug_log_wait_ms`：调试读取日志的初始等待时间（毫秒），默认 1500
- `debug_log_checks`：日志稳定性检查次数，默认 3
- `debug_log_interval_ms`：每次稳定性检查的间隔（毫秒），默认 500
- 提取统计日志级别：常规运行为 `debug`（匹配数与总提取数），在 `--verbose` 场景下查看更详细日志
- 报告来源字段：`context_type`（html/js/css/comments）与 `source_tag`（debug/normal）用于区分来源与路径
 - 关键字匹配报告：支持从上下文自动提取 `http(s)` 链接并渲染为可点击链接
 - HTML报告“可疑链接详情”默认按风险降序并过滤低风险项（≥4显示）

### JS 与联动判断口径

- eval、innerHTML、函数密度、字符熵和编码特征不再单独触发高危；使用有界词法/常量分析关联输入、解码、跳转、DOM 写入与资源插入。不会执行扫描到的 JS。
- 内联脚本和事件处理器独立分析，保留源码偏移；JSON 数据脚本及注释不当作可执行代码。跨脚本、不确定分支和复杂调用不能推断成已确认的行为。
- 视觉隐藏按实际元素/祖先属性判断，不借用可见兄弟元素、标题词语或类名；aria-hidden 不代表视觉隐藏，非零透明度不按完全透明处理。
- 同一 JS 证据在链接与脚本列表中只计一次；关键词使用 1-10 权重，结构检测使用 1-5 风险，needs_review / informational 不计高危。控制台、历史、批量汇总与报告共用去重统计口径。
- 这是有界静态分析，不是完整的 JavaScript 解释器或语义分类器，仍可能误报或漏报。旧历史和旧报告不会自动重算，需要重新扫描。

### 扫描流程与状态

- URL 抓取按深度跟随同源导航、脚本和样式，应用排除规则、去重和默认 200 URL 预算。不会自动扫描其他站点。
- 请求逐跳检查重定向落点。检测失败或响应截断标记为扫描不完整，报告不能据此给出安全结论；已有发现和错误报告仍保留。
- 自动报告名称唯一；运行中的同一任务不能重复启动，客户活跃数按实际任务状态重算。
- 静态 HTTP 抓取层的代理和地址检查不等同于无头浏览器的完整网络隔离，动态渲染需按实际部署环境另外限制出站范围。
- Clash/Mihomo 的 Fake-IP 环境可在控制台“引擎配置”中显式启用受信任本地代理兼容，或在 CLI 中同时指定 `--proxy http://127.0.0.1:7897 --allow-proxy-fake-ip`。默认严格拦截；仅允许显式配置的回环代理接管仅含 Fake-IP/公网结果的域名解析，代理失效不回退直连。必须信任代理，并在代理/网络层限制私网出站；这不是完整的 SSRF 或 DNS 重绑定防御。
