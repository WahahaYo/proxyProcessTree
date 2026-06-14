# proxyProcessTree.exe 进程树代理系统需求说明

## 一、系统目标

开发一个 Windows 程序 proxyProcessTree.exe，用于实现：

- 仅对 proxyProcessTree.exe 启动的程序及其所有子进程进行代理
- 系统其他所有程序完全不受影响
- 所有网络连接必须强制经过代理，不能被绕过

---

## 二、核心行为规则

### 2.1 进程树代理域

proxyProcessTree.exe 启动的进程进入代理域：

```
proxyProcessTree.exe
 └── a.exe (代理)
      └── b.exe (继承代理)
      └── c.exe (继承代理)
```

所有子进程递归继承代理属性。

---

### 2.2 非代理域

以下程序不受影响：

- Windows 系统进程
- explorer.exe
- edge.exe
- 用户手动启动的其他程序

---

### 2.3 网络强制规则

代理域内进程必须：

- 所有 TCP 连接走代理
- 禁止直连 socket bypass
- 支持 WinHTTP / Winsock 全覆盖

---

## 三、系统架构

### 3.1 Process Controller（进程控制器）

职责：

- 启动目标程序
- 维护 proxy PID 集合
- 追踪子进程

核心逻辑：

- CreateProcess 启动 a.exe
- WMI 或系统事件监听子进程
- 若 parent PID 属于 proxy domain，则加入代理域

---

### 3.2 Network Interceptor（网络拦截器）

👉 推荐：Windows Filtering Platform (WFP)

功能：

- 拦截所有 TCP connect 事件
- 获取 processId
- 判断是否属于 proxy domain

逻辑：

```
if processId ∈ proxyPIDs:
    redirect proxy
else:
    allow direct
```

---

### 3.3 Proxy Engine（代理转发层）

- SOCKS5 转发（推荐）
- TCP 双向流量转发
- 支持 HTTP CONNECT

---

## 四、关键设计原则

- 仅使用 PID 作为唯一判断依据
- 禁止依赖环境变量或路径判断
- 必须支持完整进程树继承
- 必须防 Winsock / WinHTTP 绕过

---

## 五、推荐实现方案（最稳定）

### 🥇 WFP + PID 进程树 + SOCKS5

这是工业级方案（VPN / Clash 内核同级）：

- WFP 负责网络拦截（系统级）
- PID tracking 负责进程树控制
- SOCKS5 负责流量转发

优点：

- 最稳定
- 最难绕过
- 性能最佳
- 可长期运行

---

## 六、实现步骤

### Step 1：进程控制模块

- CreateProcess 启动程序
- 记录 PID

---

### Step 2：进程树追踪

- WMI 监听子进程
- 或系统 snapshot polling
- 构建 proxy PID set

---

### Step 3：WFP 网络过滤

- 捕获 ALE_CONNECT 事件
- 获取 processId

---

### Step 4：代理决策

```
if PID in proxy set:
    redirect
else:
    allow
```

---

### Step 5：SOCKS5 代理转发

- 建立本地代理连接
- TCP 双向转发

---

## 七、验收标准

✔ proxyProcessTree.exe 启动的程序全部走代理  
✔ 子进程自动继承  
✔ 系统其他程序不受影响  
✔ 无网络绕过可能  

---

## 八、最终结论

最优实现方案：

> WFP（Windows Filtering Platform） + PID 进程树追踪 + SOCKS5 转发
