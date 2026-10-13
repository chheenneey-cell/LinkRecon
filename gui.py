#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LinkRecon - 暗链扫描工具 (深空蓝 · 毛玻璃风格)
"""

import os
from utils.report_paths import new_report_path
import sys
import threading
from datetime import datetime
from urllib.parse import urlparse
import re

try:
    import customtkinter as ctk
except ImportError:
    print("正在安装 customtkinter...")
    os.system("pip install customtkinter")
    import customtkinter as ctk

from tkinter import filedialog, messagebox
import tkinter as tk

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.scanner import Scanner
from core.reporter import Reporter


# ===== 主题配置 =====
THEMES = {
    "浅色": {
        "bg": "#F5F7FA",
        "surface": "#FFFFFF",
        "sidebar_bg": "#1E293B",
        "sidebar_text": "#E2E8F0",
        "primary": "#3B82F6",
        "primary_hover": "#2563EB",
        "primary_glow": "#3B82F6",
        "secondary": "#64748B",
        "success": "#10B981",
        "warning": "#F59E0B",
        "danger": "#EF4444",
        "text": "#1E293B",
        "text_secondary": "#64748B",
        "border": "#E2E8F0",
        "card_bg": "#FFFFFF",
        "card_hover": "#F8FAFC",
        "input_bg": "#F8FAFC",
        "input_border": "#CBD5E1",
        "input_focus": "#3B82F6",
        "step_active": "#3B82F6",
        "step_done": "#10B981",
        "step_pending": "#94A3B8",
        "step_glow": "#3B82F6",
        "footer_bg": "#FFFFFF",
        "divider": "#E2E8F0",
        "scrollbar": "#CBD5E1",
        "glass_border": "#E2E8F0",
    },
    "深色": {
        "bg": "#0F172A",
        "surface": "#1E293B",
        "sidebar_bg": "#0F172A",
        "sidebar_text": "#E2E8F0",
        "primary": "#60A5FA",
        "primary_hover": "#3B82F6",
        "primary_glow": "#60A5FA",
        "secondary": "#94A3B8",
        "success": "#34D399",
        "warning": "#FBBF24",
        "danger": "#F87171",
        "text": "#F1F5F9",
        "text_secondary": "#94A3B8",
        "border": "#334155",
        "card_bg": "#1E293B",
        "card_hover": "#253348",
        "input_bg": "#0F172A",
        "input_border": "#475569",
        "input_focus": "#60A5FA",
        "step_active": "#60A5FA",
        "step_done": "#34D399",
        "step_pending": "#475569",
        "step_glow": "#60A5FA",
        "footer_bg": "#1E293B",
        "divider": "#334155",
        "scrollbar": "#475569",
        "glass_border": "#334155",
    },
    "商务蓝": {
        "bg": "#F0F4F8",
        "surface": "#FFFFFF",
        "sidebar_bg": "#1E3A5F",
        "sidebar_text": "#E0E7EF",
        "primary": "#2563EB",
        "primary_hover": "#1D4ED8",
        "primary_glow": "#2563EB",
        "secondary": "#6B7280",
        "success": "#059669",
        "warning": "#D97706",
        "danger": "#DC2626",
        "text": "#111827",
        "text_secondary": "#6B7280",
        "border": "#D1D5DB",
        "card_bg": "#FFFFFF",
        "card_hover": "#F9FAFB",
        "input_bg": "#F9FAFB",
        "input_border": "#D1D5DB",
        "input_focus": "#2563EB",
        "step_active": "#2563EB",
        "step_done": "#059669",
        "step_pending": "#9CA3AF",
        "step_glow": "#2563EB",
        "footer_bg": "#FFFFFF",
        "divider": "#D1D5DB",
        "scrollbar": "#D1D5DB",
        "glass_border": "#D1D5DB",
    },
    "深空蓝": {
        "bg": "#06060e",
        "surface": "#0c0c1a",
        "sidebar_bg": "#06060e",
        "sidebar_text": "#E2E8F0",
        "primary": "#00c8ff",
        "primary_hover": "#00a0d0",
        "primary_glow": "#00c8ff",
        "secondary": "#4a5068",
        "success": "#00e5a0",
        "warning": "#ffb84d",
        "danger": "#ff4d6a",
        "text": "#e2e5ed",
        "text_secondary": "#7a809a",
        "border": "#1a1e30",
        "card_bg": "#0f1020",
        "card_hover": "#141628",
        "input_bg": "#0a0b16",
        "input_border": "#1e2240",
        "input_focus": "#00c8ff",
        "step_active": "#00c8ff",
        "step_done": "#00e5a0",
        "step_pending": "#2a2e42",
        "step_glow": "#00c8ff",
        "footer_bg": "#08081a",
        "divider": "#141830",
        "scrollbar": "#1e2240",
        "glass_border": "#1a1e30",
        "accent_rgb": "0,200,255",
    },
}


class GlowButton(ctk.CTkButton):
    """带发光效果的按钮"""

    def __init__(self, master, color_key="primary", **kwargs):
        self.color_key = color_key
        self.glow_active = False
        super().__init__(master, **kwargs)
        self._setup_glow()

    def _setup_glow(self):
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, event):
        if self.cget("state") != "disabled":
            self.configure(cursor="hand2")

    def _on_leave(self, event):
        self.configure(cursor="arrow")


class TypeCard(ctk.CTkFrame):
    """可交互的目标类型卡片"""

    def __init__(self, master, icon_text, title, desc, value, colors, callback, **kwargs):
        super().__init__(
            master,
            fg_color=colors["card_bg"],
            border_width=2,
            border_color=colors["border"],
            corner_radius=14,
            height=130,
            **kwargs
        )
        self.pack_propagate(False)
        self.colors = colors
        self.value = value
        self.is_selected = False
        self.callback = callback

        # 图标区域
        self.icon_frame = ctk.CTkFrame(
            self, fg_color="transparent", width=50, height=50
        )
        self.icon_frame.pack(pady=(18, 6))
        self.icon_frame.pack_propagate(False)

        self.icon_label = ctk.CTkLabel(
            self.icon_frame,
            text=icon_text,
            font=ctk.CTkFont(size=26),
            width=50, height=50,
            corner_radius=12,
            fg_color=colors["border"],
            text_color=colors["text_secondary"]
        )
        self.icon_label.pack()

        # 标题
        self.title_label = ctk.CTkLabel(
            self, text=title,
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color=colors["text"]
        )
        self.title_label.pack(pady=(0, 2))

        # 描述
        self.desc_label = ctk.CTkLabel(
            self, text=desc,
            font=ctk.CTkFont(size=11),
            text_color=colors["text_secondary"]
        )
        self.desc_label.pack(pady=(0, 14))

        # 绑定点击
        self._bind_click(self)
        for child in self.winfo_children():
            self._bind_click(child)

    def _bind_click(self, widget):
        widget.bind("<Button-1>", lambda e: self.callback(self.value))
        widget.bind("<Enter>", self._on_hover_enter)
        widget.bind("<Leave>", self._on_hover_leave)

    def _on_hover_enter(self, event):
        if not self.is_selected:
            self.configure(border_color=self.colors["glass_border"], fg_color=self.colors["card_hover"])

    def _on_hover_leave(self, event):
        if not self.is_selected:
            self.configure(border_color=self.colors["border"], fg_color=self.colors["card_bg"])

    def set_selected(self, selected):
        self.is_selected = selected
        if selected:
            self.configure(
                border_color=self.colors["primary"],
                fg_color=self.colors["card_hover"]
            )
            self.icon_label.configure(
                fg_color=self.colors["primary"],
                text_color="#000000"
            )
        else:
            self.configure(
                border_color=self.colors["border"],
                fg_color=self.colors["card_bg"]
            )
            self.icon_label.configure(
                fg_color=self.colors["border"],
                text_color=self.colors["text_secondary"]
            )


class StepIndicator(ctk.CTkFrame):
    """步骤指示器"""

    def __init__(self, master, step_names, colors, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.colors = colors
        self.indicators = []

        for i, name in enumerate(step_names):
            container = ctk.CTkFrame(self, fg_color="transparent")
            container.pack(side="left", padx=12)

            # 步骤圆圈
            circle = ctk.CTkLabel(
                container,
                text=str(i + 1),
                width=36, height=36,
                corner_radius=18,
                font=ctk.CTkFont(size=14, weight="bold"),
                fg_color=colors["step_pending"],
                text_color="#FFFFFF"
            )
            circle.pack()

            # 步骤名称
            label = ctk.CTkLabel(
                container,
                text=name,
                font=ctk.CTkFont(size=11),
                text_color=colors["text_secondary"]
            )
            label.pack(pady=(6, 0))

            self.indicators.append({"circle": circle, "label": label})

            # 连接线
            if i < len(step_names) - 1:
                line = ctk.CTkFrame(
                    self,
                    width=60, height=3,
                    corner_radius=1,
                    fg_color=colors["border"]
                )
                line.pack(side="left", padx=4, pady=(0, 22))
                self.indicators[-1]["line"] = line

    def update_steps(self, current):
        for i, ind in enumerate(self.indicators):
            if i < current:
                ind["circle"].configure(
                    fg_color=self.colors["step_done"],
                    text_color="#FFFFFF"
                )
                ind["label"].configure(text_color=self.colors["success"])
                if "line" in ind:
                    ind["line"].configure(fg_color=self.colors["step_done"])
            elif i == current:
                ind["circle"].configure(
                    fg_color=self.colors["step_active"],
                    text_color="#000000"
                )
                ind["label"].configure(text_color=self.colors["primary"])
                if "line" in ind:
                    ind["line"].configure(fg_color=self.colors["border"])
            else:
                ind["circle"].configure(
                    fg_color=self.colors["step_pending"],
                    text_color="#FFFFFF"
                )
                ind["label"].configure(text_color=self.colors["text_secondary"])
                if "line" in ind:
                    ind["line"].configure(fg_color=self.colors["border"])


class WizardApp(ctk.CTk):
    """LinkRecon 向导式扫描工具"""

    def __init__(self):
        super().__init__()

        self.title("LinkRecon - 暗链扫描工具")
        self.geometry("960x680")
        self.minsize(900, 650)

        # 当前主题
        self.current_theme_name = "深空蓝"
        self.colors = THEMES[self.current_theme_name]

        # 当前步骤
        self.current_step = 0
        self.total_steps = 4

        # 扫描状态
        self.scanning = False
        self.scan_thread = None

        # 扫描配置
        self.scan_config = {
            "target": "",
            "target_type": "url",
            "mode": "deep",
            "format": "html",
            "depth": 3,
            "threads": 8,
            "timeout": 30,
            "keyword_file": "",
            "output_dir": os.path.join(os.getcwd(), "reports"),
            "headless": False
        }

        # 配置外观 - 根据主题自动适配
        self._apply_appearance()

        # 创建界面
        self.create_ui()
        self.show_step(0)

    def _apply_appearance(self):
        """根据当前主题应用外观模式"""
        if self.current_theme_name in ("深色", "深空蓝"):
            ctk.set_appearance_mode("dark")
        else:
            ctk.set_appearance_mode("light")

    def create_ui(self):
        """创建主界面"""
        # 主容器
        self.main_container = ctk.CTkFrame(
            self, fg_color=self.colors["bg"], corner_radius=0
        )
        self.main_container.pack(fill="both", expand=True)

        # 顶部导航栏
        self.create_header()

        # 内容区域
        self.content_frame = ctk.CTkFrame(
            self.main_container, fg_color="transparent"
        )
        self.content_frame.pack(fill="both", expand=True, padx=40, pady=(0, 20))

        # 创建所有步骤页面
        self.steps = []
        self.create_step1_target()
        self.create_step2_config()
        self.create_step3_advanced()
        self.create_step4_execute()

        # 底部按钮栏
        self.create_footer()

    def create_header(self):
        """创建顶部导航栏"""
        header = ctk.CTkFrame(
            self.main_container,
            fg_color=self.colors["surface"],
            height=85,
            corner_radius=0
        )
        header.pack(fill="x")
        header.pack_propagate(False)

        # 左侧 Logo
        logo_frame = ctk.CTkFrame(header, fg_color="transparent")
        logo_frame.pack(side="left", padx=30)

        # Logo 图标背景
        logo_icon_bg = ctk.CTkFrame(
            logo_frame,
            width=36, height=36,
            corner_radius=10,
            fg_color=self.colors["primary"]
        )
        logo_icon_bg.pack(side="left")
        logo_icon_bg.pack_propagate(False)

        ctk.CTkLabel(
            logo_icon_bg,
            text="◎",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#000000" if self.current_theme_name == "深空蓝" else "#FFFFFF"
        ).pack(expand=True)

        ctk.CTkLabel(
            logo_frame,
            text="  LinkRecon",
            font=ctk.CTkFont(family="Microsoft YaHei", size=22, weight="bold"),
            text_color=self.colors["text"]
        ).pack(side="left", padx=(8, 0))

        ctk.CTkLabel(
            logo_frame,
            text=" 暗链扫描工具",
            font=ctk.CTkFont(size=13),
            text_color=self.colors["text_secondary"]
        ).pack(side="left", padx=(2, 0))

        # 步骤指示器（居中）
        steps_container = ctk.CTkFrame(header, fg_color="transparent")
        steps_container.pack(expand=True)

        step_names = ["扫描目标", "扫描配置", "高级选项", "执行扫描"]
        self.step_ind = StepIndicator(
            steps_container, step_names, self.colors
        )
        self.step_ind.pack()

        # 右侧主题切换
        theme_frame = ctk.CTkFrame(header, fg_color="transparent")
        theme_frame.pack(side="right", padx=30)

        ctk.CTkLabel(
            theme_frame,
            text="主题",
            font=ctk.CTkFont(size=11),
            text_color=self.colors["text_secondary"]
        ).pack(side="left", padx=(0, 8))

        self.theme_var = ctk.StringVar(value=self.current_theme_name)
        theme_menu = ctk.CTkOptionMenu(
            theme_frame,
            variable=self.theme_var,
            values=list(THEMES.keys()),
            command=self.change_theme,
            width=90,
            height=30,
            corner_radius=8,
            fg_color=self.colors["border"],
            button_color=self.colors["primary"],
            button_hover_color=self.colors["primary_hover"],
            dropdown_fg_color=self.colors["card_bg"],
            dropdown_hover_color=self.colors["card_hover"],
        )
        theme_menu.pack(side="left")

    def create_step1_target(self):
        """步骤1：扫描目标"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")

        # 标题
        ctk.CTkLabel(
            frame,
            text="选择扫描目标",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            frame,
            text="请选择要扫描的目标类型，并输入或选择目标路径",
            font=ctk.CTkFont(size=13),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 30))

        # 目标类型卡片
        cards_frame = ctk.CTkFrame(frame, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, 30))

        self.target_type_var = ctk.StringVar(value="url")
        self.type_cards = []

        card_data = [
            ("◎", "URL 扫描", "扫描网站链接", "url"),
            ("▤", "文件扫描", "扫描单个文件", "file"),
            ("⊞", "目录扫描", "扫描整个目录", "dir"),
        ]

        for i, (icon, title, desc, value) in enumerate(card_data):
            card = TypeCard(
                cards_frame, icon, title, desc, value,
                self.colors, self.select_target_type
            )
            card.pack(
                side="left", fill="x", expand=True,
                padx=(0, 15) if i < 2 else (0, 0)
            )
            self.type_cards.append(card)

        # 默认选中第一个
        self.type_cards[0].set_selected(True)

        # 输入区域
        ctk.CTkLabel(
            frame,
            text="扫描目标",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 8))

        input_frame = ctk.CTkFrame(frame, fg_color="transparent")
        input_frame.pack(fill="x")

        self.target_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="请输入网址，如 https://example.com",
            height=46,
            font=ctk.CTkFont(size=13),
            fg_color=self.colors["input_bg"],
            border_color=self.colors["input_border"],
            corner_radius=10,
            text_color=self.colors["text"],
            placeholder_text_color=self.colors["text_secondary"],
        )
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))

        self.btn_browse = ctk.CTkButton(
            input_frame,
            text="浏览…",
            width=80,
            height=46,
            corner_radius=10,
            font=ctk.CTkFont(size=12),
            fg_color=self.colors["border"],
            hover_color=self.colors["card_hover"],
            text_color=self.colors["text_secondary"],
            command=self.browse_target,
            state="disabled"
        )
        self.btn_browse.pack(side="right")

        self.steps.append(frame)

    def select_target_type(self, value):
        """选择目标类型"""
        self.target_type_var.set(value)
        self.scan_config["target_type"] = value

        for card in self.type_cards:
            card.set_selected(card.value == value)

        # 更新输入框提示
        self.target_entry.delete(0, "end")
        if value == "url":
            self.target_entry.configure(
                placeholder_text="请输入网址，如 https://example.com"
            )
            self.btn_browse.configure(state="disabled")
        elif value == "file":
            self.target_entry.configure(
                placeholder_text="请选择或输入文件路径…"
            )
            self.btn_browse.configure(state="normal")
        else:
            self.target_entry.configure(
                placeholder_text="请选择或输入目录路径…"
            )
            self.btn_browse.configure(state="normal")

    def create_step2_config(self):
        """步骤2：扫描配置"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")

        ctk.CTkLabel(
            frame,
            text="扫描配置",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            frame,
            text="选择扫描模式和报告格式",
            font=ctk.CTkFont(size=13),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 30))

        # 扫描模式
        ctk.CTkLabel(
            frame,
            text="扫描模式",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 12))

        mode_frame = ctk.CTkFrame(frame, fg_color="transparent")
        mode_frame.pack(fill="x", pady=(0, 28))

        self.mode_var = ctk.StringVar(value="deep")
        self.mode_cards = []

        mode_data = [
            ("⚡", "快速模式", "仅检测基本暗链，速度最快", "fast"),
            ("◎", "标准模式", "JS/HTML/CSS分析，推荐日常使用", "standard"),
            ("◈", "深度模式", "全部检测模块，适合深度审计", "deep"),
        ]

        for i, (icon, title, desc, value) in enumerate(mode_data):
            card = TypeCard(
                mode_frame, icon, title, desc, value,
                self.colors, self.select_mode
            )
            card.pack(
                side="left", fill="x", expand=True,
                padx=(0, 15) if i < 2 else (0, 0)
            )
            if value == "deep":
                card.set_selected(True)
            self.mode_cards.append(card)

        # 报告格式
        ctk.CTkLabel(
            frame,
            text="报告格式",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 12))

        format_frame = ctk.CTkFrame(frame, fg_color="transparent")
        format_frame.pack(fill="x")

        self.format_var = ctk.StringVar(value="html")
        self.format_cards = []

        format_data = [
            ("-", "TXT", "纯文本格式", "txt"),
            ("◎", "HTML", "网页报告", "html"),
            "{…}", "JSON", "结构化数据", "csv",
            "≡", "CSV", "表格数据", "csv",
        ]
        # 修正 JSON 的 value
        format_data = [
            ("-", "TXT", "纯文本格式", "txt"),
            ("◎", "HTML", "网页报告", "html"),
            ("{}", "JSON", "结构化数据", "json"),
            ("≡", "CSV", "表格数据", "csv"),
        ]

        for i, (icon, title, desc, value) in enumerate(format_data):
            card = TypeCard(
                format_frame, icon, title, desc, value,
                self.colors, self.select_format
            )
            card.configure(height=100)
            card.pack(
                side="left", fill="x", expand=True,
                padx=(0, 12) if i < 3 else (0, 0)
            )
            if value == "html":
                card.set_selected(True)
            self.format_cards.append(card)

        self.steps.append(frame)

    def select_mode(self, value):
        """选择扫描模式"""
        self.mode_var.set(value)
        self.scan_config["mode"] = value
        for card in self.mode_cards:
            card.set_selected(card.value == value)

    def select_format(self, value):
        """选择报告格式"""
        self.format_var.set(value)
        self.scan_config["format"] = value
        for card in self.format_cards:
            card.set_selected(card.value == value)

    def create_step3_advanced(self):
        """步骤3：高级选项"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")

        ctk.CTkLabel(
            frame,
            text="高级选项",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            frame,
            text="调整扫描参数以满足特定需求（可选）",
            font=ctk.CTkFont(size=13),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 28))

        # 参数卡片容器
        params_card = ctk.CTkFrame(
            frame,
            fg_color=self.colors["card_bg"],
            border_width=1,
            border_color=self.colors["border"],
            corner_radius=14
        )
        params_card.pack(fill="x", pady=(0, 16))

        inner = ctk.CTkFrame(params_card, fg_color="transparent")
        inner.pack(fill="x", padx=32, pady=28)

        # --- 第一行 ---
        row1 = ctk.CTkFrame(inner, fg_color="transparent")
        row1.pack(fill="x", pady=(0, 20))

        # 扫描深度
        self._create_param_field(
            row1, "扫描深度", "递归扫描的层数，0 表示仅当前",
            "3", "depth_var"
        )

        # 线程数
        self._create_param_field(
            row1, "并发线程数", "1–100，越大越快但消耗资源",
            "8", "threads_var"
        )

        # --- 第二行 ---
        row2 = ctk.CTkFrame(inner, fg_color="transparent")
        row2.pack(fill="x")

        # 超时
        self._create_param_field(
            row2, "请求超时（秒）", "单个请求的最大等待时间",
            "30", "timeout_var"
        )

        # 关键字文件
        kw_frame = ctk.CTkFrame(row2, fg_color="transparent")
        kw_frame.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            kw_frame, text="自定义关键字文件",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", pady=(0, 5))
        ctk.CTkLabel(
            kw_frame, text="留空使用默认规则库",
            font=ctk.CTkFont(size=11),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 8))

        kw_input = ctk.CTkFrame(kw_frame, fg_color="transparent")
        kw_input.pack(fill="x")

        self.keyword_var = ctk.StringVar()
        ctk.CTkEntry(
            kw_input,
            textvariable=self.keyword_var,
            height=42,
            placeholder_text="keywords_example.txt",
            font=ctk.CTkFont(size=13),
            fg_color=self.colors["input_bg"],
            border_color=self.colors["input_border"],
            corner_radius=10,
            text_color=self.colors["text"],
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            kw_input,
            text="浏览",
            width=70, height=42,
            corner_radius=10,
            font=ctk.CTkFont(size=12),
            fg_color=self.colors["border"],
            hover_color=self.colors["card_hover"],
            text_color=self.colors["text_secondary"],
            command=self.browse_keyword
        ).pack(side="right")

        # --- 无头浏览器选项 ---
        options_card = ctk.CTkFrame(
            frame,
            fg_color=self.colors["card_bg"],
            border_width=1,
            border_color=self.colors["border"],
            corner_radius=14
        )
        options_card.pack(fill="x")

        options_inner = ctk.CTkFrame(options_card, fg_color="transparent")
        options_inner.pack(fill="x", padx=32, pady=22)

        self.headless_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            options_inner,
            text="启用无头浏览器扫描（增强动态内容检测）",
            variable=self.headless_var,
            font=ctk.CTkFont(size=13),
            checkbox_width=22, checkbox_height=22,
            checkmark_color="#000000" if self.current_theme_name == "深空蓝" else "#FFFFFF",
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            text_color=self.colors["text"],
        ).pack(anchor="w")

        self.steps.append(frame)

    def _create_param_field(self, parent, label, desc, default, var_name):
        """创建参数输入字段"""
        field_frame = ctk.CTkFrame(parent, fg_color="transparent")
        field_frame.pack(side="left", fill="x", expand=True, padx=(0, 20))

        ctk.CTkLabel(
            field_frame, text=label,
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", pady=(0, 5))
        ctk.CTkLabel(
            field_frame, text=desc,
            font=ctk.CTkFont(size=11),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 8))

        var = ctk.StringVar(value=default)
        setattr(self, var_name, var)

        ctk.CTkEntry(
            field_frame,
            textvariable=var,
            height=42,
            font=ctk.CTkFont(size=13),
            fg_color=self.colors["input_bg"],
            border_color=self.colors["input_border"],
            corner_radius=10,
            text_color=self.colors["text"],
        ).pack(fill="x")

    def create_step4_execute(self):
        """步骤4：执行扫描"""
        frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")

        ctk.CTkLabel(
            frame,
            text="执行扫描",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", pady=(0, 5))

        ctk.CTkLabel(
            frame,
            text="确认配置并开始扫描",
            font=ctk.CTkFont(size=13),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 28))

        # 配置摘要卡片
        summary_card = ctk.CTkFrame(
            frame,
            fg_color=self.colors["card_bg"],
            border_width=1,
            border_color=self.colors["border"],
            corner_radius=14
        )
        summary_card.pack(fill="x", pady=(0, 16))

        summary_inner = ctk.CTkFrame(summary_card, fg_color="transparent")
        summary_inner.pack(fill="x", padx=32, pady=28)

        ctk.CTkLabel(
            summary_inner,
            text="配置摘要",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color=self.colors["text"]
        ).pack(anchor="w", pady=(0, 16))

        self.summary_labels = {}
        config_items = [
            ("扫描目标", "target"),
            ("扫描模式", "mode"),
            ("报告格式", "format"),
            ("扫描深度", "depth"),
            ("线程数", "threads"),
            ("超时时间", "timeout"),
        ]

        for label_text, key in config_items:
            row = ctk.CTkFrame(summary_inner, fg_color="transparent")
            row.pack(fill="x", pady=4)

            ctk.CTkLabel(
                row, text=f"{label_text}:",
                font=ctk.CTkFont(size=13),
                text_color=self.colors["text_secondary"],
                width=100, anchor="w"
            ).pack(side="left")

            val = ctk.CTkLabel(
                row, text="—",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=self.colors["text"],
                anchor="w"
            )
            val.pack(side="left", fill="x", expand=True)
            self.summary_labels[key] = val

        # 分割线
        ctk.CTkFrame(
            frame, height=1,
            fg_color=self.colors["divider"]
        ).pack(fill="x", pady=(0, 16))

        # 输出目录
        ctk.CTkLabel(
            frame, text="输出目录",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color=self.colors["text_secondary"]
        ).pack(anchor="w", pady=(0, 8))

        output_input = ctk.CTkFrame(frame, fg_color="transparent")
        output_input.pack(fill="x", pady=(0, 20))

        self.output_var = ctk.StringVar(value=self.scan_config["output_dir"])
        ctk.CTkEntry(
            output_input,
            textvariable=self.output_var,
            height=42,
            font=ctk.CTkFont(size=13),
            fg_color=self.colors["input_bg"],
            border_color=self.colors["input_border"],
            corner_radius=10,
            text_color=self.colors["text"],
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            output_input, text="浏览",
            width=70, height=42, corner_radius=10,
            font=ctk.CTkFont(size=12),
            fg_color=self.colors["border"],
            hover_color=self.colors["card_hover"],
            text_color=self.colors["text_secondary"],
            command=self.browse_output
        ).pack(side="right")

        # 扫描按钮
        self.scan_button = ctk.CTkButton(
            frame,
            text="开始扫描",
            font=ctk.CTkFont(size=16, weight="bold"),
            height=52,
            corner_radius=12,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            text_color="#000000" if self.current_theme_name == "深空蓝" else "#FFFFFF",
            command=self.start_scan
        )
        self.scan_button.pack(fill="x")

        self.steps.append(frame)

    def create_footer(self):
        """创建底部按钮栏"""
        footer = ctk.CTkFrame(
            self.main_container,
            fg_color=self.colors["footer_bg"],
            height=65,
            corner_radius=0
        )
        footer.pack(fill="x", side="bottom")
        footer.pack_propagate(False)

        # 底部上边线
        ctk.CTkFrame(
            footer, height=1,
            fg_color=self.colors["divider"]
        ).pack(fill="x")

        btn_frame = ctk.CTkFrame(footer, fg_color="transparent")
        btn_frame.pack(expand=True)

        self.btn_prev = ctk.CTkButton(
            btn_frame,
            text="← 上一步",
            font=ctk.CTkFont(size=13),
            width=130, height=40,
            corner_radius=10,
            fg_color=self.colors["border"],
            hover_color=self.colors["card_hover"],
            text_color=self.colors["text_secondary"],
            command=self.prev_step
        )
        self.btn_prev.pack(side="left", padx=10)

        self.btn_next = ctk.CTkButton(
            btn_frame,
            text="下一步 →",
            font=ctk.CTkFont(size=13, weight="bold"),
            width=130, height=40,
            corner_radius=10,
            fg_color=self.colors["primary"],
            hover_color=self.colors["primary_hover"],
            text_color="#000000" if self.current_theme_name == "深空蓝" else "#FFFFFF",
            command=self.next_step
        )
        self.btn_next.pack(side="left", padx=10)

    def show_step(self, index):
        """显示指定步骤"""
        self.current_step = index

        for step in self.steps:
            step.pack_forget()

        self.steps[index].pack(fill="both", expand=True)

        # 更新步骤指示器
        self.step_ind.update_steps(index)

        # 更新按钮
        self.btn_prev.configure(state="normal" if index > 0 else "disabled")

        if index == self.total_steps - 1:
            self.btn_next.configure(text="开始扫描", state="disabled")
        else:
            self.btn_next.configure(text="下一步 →", state="normal")

        if index == 3:
            self.update_summary()

    def prev_step(self):
        if self.current_step > 0:
            self.show_step(self.current_step - 1)

    def next_step(self):
        if not self.validate_current_step():
            return
        if self.current_step < self.total_steps - 1:
            self.show_step(self.current_step + 1)

    def validate_current_step(self):
        if self.current_step == 0:
            target = self.target_entry.get().strip()
            if not target:
                messagebox.showerror("错误", "请输入扫描目标")
                return False
            self.scan_config["target"] = target
        elif self.current_step == 1:
            self.scan_config["mode"] = self.mode_var.get()
            self.scan_config["format"] = self.format_var.get()
        elif self.current_step == 2:
            try:
                depth = int(self.depth_var.get())
                if depth < 0:
                    messagebox.showerror("错误", "扫描深度不能为负数")
                    return False
                self.scan_config["depth"] = depth
            except ValueError:
                messagebox.showerror("错误", "扫描深度必须是数字")
                return False
            try:
                threads = int(self.threads_var.get())
                if threads < 1 or threads > 100:
                    messagebox.showerror("错误", "线程数必须在1-100之间")
                    return False
                self.scan_config["threads"] = threads
            except ValueError:
                messagebox.showerror("错误", "线程数必须是数字")
                return False
            try:
                timeout = int(self.timeout_var.get())
                if timeout < 1:
                    messagebox.showerror("错误", "超时时间必须大于0")
                    return False
                self.scan_config["timeout"] = timeout
            except ValueError:
                messagebox.showerror("错误", "超时时间必须是数字")
                return False
            self.scan_config["keyword_file"] = self.keyword_var.get().strip()
            self.scan_config["headless"] = self.headless_var.get()
        return True

    def update_summary(self):
        mode_names = {"fast": "快速模式", "standard": "标准模式", "deep": "深度模式"}
        format_names = {"txt": "TXT", "html": "HTML", "json": "JSON", "csv": "CSV"}

        self.summary_labels["target"].configure(text=self.scan_config["target"])
        self.summary_labels["mode"].configure(
            text=mode_names.get(self.scan_config["mode"], self.scan_config["mode"])
        )
        self.summary_labels["format"].configure(
            text=format_names.get(self.scan_config["format"], self.scan_config["format"])
        )
        self.summary_labels["depth"].configure(text=str(self.scan_config["depth"]))
        self.summary_labels["threads"].configure(text=str(self.scan_config["threads"]))
        self.summary_labels["timeout"].configure(
            text=f"{self.scan_config['timeout']} 秒"
        )

    def browse_target(self):
        target_type = self.target_type_var.get()
        if target_type == "file":
            filename = filedialog.askopenfilename(
                title="选择扫描目标文件",
                filetypes=[
                    ("HTML文件", "*.html *.htm"),
                    ("文本文件", "*.txt"),
                    ("所有文件", "*.*"),
                ],
            )
            if filename:
                self.target_entry.delete(0, "end")
                self.target_entry.insert(0, filename)
        elif target_type == "dir":
            directory = filedialog.askdirectory(title="选择扫描目标目录")
            if directory:
                self.target_entry.delete(0, "end")
                self.target_entry.insert(0, directory)

    def browse_keyword(self):
        filename = filedialog.askopenfilename(
            title="选择关键字文件",
            filetypes=[("文本文件", "*.txt"), ("所有文件", "*.*")],
        )
        if filename:
            self.keyword_var.set(filename)

    def browse_output(self):
        directory = filedialog.askdirectory(title="选择报告输出目录")
        if directory:
            self.output_var.set(directory)
            self.scan_config["output_dir"] = directory

    def change_theme(self, theme_name):
        self.current_theme_name = theme_name
        self.colors = THEMES[theme_name]
        self._apply_appearance()

        for widget in self.main_container.winfo_children():
            widget.destroy()

        self.create_ui()
        self.show_step(self.current_step)

    def start_scan(self):
        if self.scanning:
            messagebox.showwarning("警告", "扫描正在进行中")
            return
        self.scanning = True
        self.scan_button.configure(state="disabled", text="扫描中…")
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()

    def run_scan(self):
        try:
            start_time = datetime.now()
            config = self.scan_config
            os.makedirs(config["output_dir"], exist_ok=True)

            scan_config = Config()
            target = config["target"]

            if target.startswith(("http://", "https://")):
                parsed_url = urlparse(target)
                domain = parsed_url.netloc
                if (
                    re.match(r"^127\.0\.0\.1(:\d+)?$", domain)
                    or re.match(r"^localhost(:\d+)?$", domain)
                    or re.match(r"^10\.\d+\.\d+\.\d+(:\d+)?$", domain)
                    or re.match(
                        r"^172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+(:\d+)?$", domain
                    )
                    or re.match(r"^192\.168\.\d+\.\d+(:\d+)?$", domain)
                ):
                    scan_config.target_type = "internal_url"
                else:
                    scan_config.target_type = "external_url"
            elif os.path.isfile(target):
                scan_config.target_type = "local_file"
            elif os.path.isdir(target):
                scan_config.target_type = "local_directory"
            else:
                self.after(
                    0,
                    lambda: messagebox.showerror("错误", "无效的扫描目标"),
                )
                return

            scan_config.target = target
            scan_config.crawl_depth = config["depth"]
            scan_config.depth = config["depth"]
            scan_config.scan_mode = config["mode"]
            scan_config.mode = config["mode"]
            scan_config._set_mode_config()
            scan_config.threads = config["threads"]
            scan_config.timeout = config["timeout"]
            scan_config.keywords_file = config["keyword_file"] or None
            scan_config.report_type = config["format"]
            scan_config.debug = False
            scan_config.use_headless_browser = config["headless"]
            scan_config.js_wait_time = 3
            scan_config.headless_auto_download = True

            scanner = Scanner(scan_config)
            result = scanner.scan()

            end_time = datetime.now()
            duration = str(end_time - start_time)

            report_file = new_report_path(config["output_dir"], config['format'])
            scan_config.report_file = report_file
            scan_config.target = target

            reporter = Reporter(scan_config)
            report_path = reporter.generate_report(result, duration)

            self.after(0, lambda: self.show_result(result, report_path))

        except Exception as e:
            error_msg = str(e)
            self.after(
                0,
                lambda: messagebox.showerror(
                    "扫描错误", f"扫描过程中发生错误:\n{error_msg}"
                ),
            )
        finally:
            self.after(
                0,
                lambda: self.scan_button.configure(
                    state="normal", text="开始扫描"
                ),
            )
            self.scanning = False

    def show_result(self, result, report_path):
        result_window = ctk.CTkToplevel(self)
        result_window.title("扫描结果")
        result_window.geometry("700x500")
        result_window.transient(self)

        text_box = ctk.CTkTextbox(
            result_window,
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="word",
            fg_color=self.colors["input_bg"],
            text_color=self.colors["text"],
        )
        text_box.pack(fill="both", expand=True, padx=20, pady=20)

        result_text = (
            "╔══════════════════════════════════════════════════╗\n"
            "║                  扫描完成                        ║\n"
            "╚══════════════════════════════════════════════════╝\n\n"
            f"扫描文件: {result.get('scanned_files', 0)}\n"
            f"扫描URL: {result.get('scanned_urls', 0)}\n"
            f"发现问题: {result.get('total_issues', 0)}\n\n"
            f"报告已保存至: {report_path}\n"
        )

        text_box.insert("1.0", result_text)
        text_box.configure(state="disabled")


def main():
    app = WizardApp()
    app.mainloop()


if __name__ == "__main__":
    main()
