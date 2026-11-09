# ShodanViewer

基于Qt6的shodan桌面搜索客户端，C++编写

> ⚠️ **本项目为非官方第三方工具**，与Shodan ®, LLC 无任何隶属或合作关系
> 本项目使用需自备shodan API Key，并遵守[shodan服务条款](https://static.shodan.io/legal/terms.html)

[![Build](https://github.com/luceminx/shodanviewer/actions/workflows/ci.yml/badge.svg)](https://github.com/luceminx/shodanviewer/actions/workflows/ci.yml)
[![GitHub release](https://img.shields.io/github/v/release/luceminx/ShodanViewer.svg?style=flat-square&include_prereleases)](https://github.com/luceminx/ShodanViewer/releases)
## 构建

Requirements: Qt 6 (Widgets, Network, Sql), CMake 3.21+, and a C++20 compiler

```bash
cmake -S . -B build
cmake --build build --config Release
```

## 首次运行
打开设置，填写API Key, 之后在搜索框使用[shodan语法](https://www.shodan.io/search/filters)进行搜索

## 缓存策略

- 缓存包括查询语句，页码，请求时间，和返回的数据
- 缓存页码是作为快照，它们被重复使用，除非重新刷新当前索引。导出时可选是否使用缓存
- 内存中包含当前结果页面，sqlite会持久化请求预览过的数据进行缓存，导出部分则不再缓存
- 刷新当前查询（指向当前页面）会覆盖sqlite对应缓存部分

## 功能
- 标签页结果预览
- 支持右键预览和快速复制IP及完整JSON
- 支持导出JSON或CSV文件，同时导出支持缓存+缺失页（一定程度上节省credits），或全部请求新数据
- 支持证书序列号查询
- 支持输入提示
- 支持最近5条历史查询语句展示
- 首页语法展示

## 参考
- 界面参考了[fofa_viewer](https://github.com/wgpsec/fofa_viewer)的设计
