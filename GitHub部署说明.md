# 圣诞树 · GitHub 部署与共享祝福池

仓库：https://github.com/cyh003/christmas-tree

---

## 一、已经做好的部分

| 项 | 状态 |
|---|---|
| GitHub 仓库 | ✅ 已创建（公开）`cyh003/christmas-tree` |
| 代码推送 | ✅ 已完成 |
| GitHub Pages | ⬜ 需要你在网页上点一下开启（见下方） |
| 共享祝福池前端 | ✅ 代码已写好，等填 Supabase 的 key |

---

## 二、开启 GitHub Pages（1 分钟）

1. 打开 https://github.com/cyh003/christmas-tree/settings/pages
2. **Source** 选 `Deploy from a branch`
3. **Branch** 选 `main`，目录选 `/ (root)`
4. 点 **Save**
5. 等 1～2 分钟，网址就有了：

```
https://cyh003.github.io/christmas-tree/
```

> 也可以让我帮你调 API 开启，但需要仓库有 `pages:write` 权限的 token，用网页点更快。

**这个网址可以直接发到微信聊天里，点开就能玩。**

---

## 三、共享祝福池（让所有人看到彼此的祝福）

### 3.1 为什么这个必须要有服务端

你原来的「分享」是**把心愿编码进链接**（`#w=xxx`），朋友打开链接能看到你写的心愿。
那是「传纸条」——只能传给你发给的人。

**共享祝福池**是另一回事：所有人写的心愿进同一个池子，谁打开都能看到别人的。
浏览器之间不能直接互相写数据，所以必须有服务端存一下。

### 3.2 建 Supabase 项目（免费）

1. 打开 https://supabase.com ，用 GitHub 账号登录
2. **New project**
   - Name：`christmas-tree`
   - Database Password：随便设一个强密码（**记下来**，以后要用）
   - Region：选 **Northeast Asia (Tokyo)** 或 **Southeast Asia (Singapore)**，国内访问快
3. 等 1～2 分钟项目初始化完成

### 3.3 建表

1. 左侧菜单点 **SQL Editor**
2. **New query**
3. 把 `SUPABASE_SETUP.sql` 全文粘贴进去
4. 点 **Run**

跑完会看到 `total_wishes = 0`，说明表建好了。

### 3.4 拿两个 key

1. 左侧 **Project Settings**（齿轮）→ **API**
2. 复制这两项：

| 名称 | 长相 | 填到哪 |
|---|---|---|
| **Project URL** | `https://xxxxx.supabase.co` | `CONFIG.cloud.url` |
| **anon public** | `eyJhbGciOiJIUzI1NiIs...`（很长） | `CONFIG.cloud.anonKey` |

⚠️ **绝对不要**用 `service_role` key —— 那个能绕过所有权限，泄露了数据库就被人随便改了。

> `anon` key 本来就是给前端用的公开密钥，写在 HTML 里**不是泄露**。
> 真正的防线是数据库的 RLS 策略（`SUPABASE_SETUP.sql` 第 3～6 步）：
> 只能读、只能插、不能改不能删。

### 3.5 填进代码

打开 `christmas-tree.html`，找到 `CONFIG.cloud`：

```js
cloud: {
  url: 'https://xxxxx.supabase.co',        // ← 填这里
  anonKey: 'eyJhbGciOiJIUzI1NiIs...',      // ← 填这里
  table: 'wishes',
  maxFetch: 60
}
```

填完保存，重新推送：

```powershell
cd C:\Users\86182\Documents\deepseek-harness\default-workspace
git add -A
git commit -m "开启共享祝福池"
git push
```

---

## 四、填了 key 之后会变成什么样

| 功能 | 之前 | 之后 |
|---|---|---|
| 写心愿 | 只存在自己手机里 | **同时上传到云端** |
| 打开页面 | 只看自己的 | **树上会飘出别人最新的 4 条祝福** |
| 底部「墙」按钮 | 显示"纯本地模式" | **列出所有人的祝福 + 时间**（刚刚 / 3 分钟前） |
| 断网时写心愿 | 正常 | 正常，**心愿进队列，联网后自动补发** |
| 别人删改我的祝福 | — | **做不到**（RLS 只给了 insert + select） |

---

## 五、文件清单

| 文件 | 说明 |
|---|---|
| `index.html` | 部署入口（GitHub Pages 默认找这个） |
| `christmas-tree.html` | 同一内容，改这个也行 |
| `SUPABASE_SETUP.sql` | 数据库建表脚本，粘进 Supabase 跑一次 |
| `.nojekyll` | 告诉 Pages 别用 Jekyll 处理，避免下划线文件被忽略 |
| `微信打开说明.md` | 微信端适配说明 |

---

## 六、常见问题

**Q：GitHub Pages 国内访问慢/打不开？**
A：正常。GitHub Pages 的 CDN 在国内不稳定。三个替代：
1. 用 **Gitee Pages**（国内快，但需要实名）
2. 用 **腾讯云 COS / 阿里云 OSS** 静态网站功能（几块钱，国内秒开）
3. 自己买个域名 + Cloudflare 代理

**Q：能不能不用 Supabase，直接用 GitHub 存心愿？**
A：不行。GitHub 是只读的静态托管，浏览器不能往里写东西。想存数据必须有后端。

**Q：Supabase 免费额度够吗？**
A：够。免费版 500MB 数据库 + 每月 5GB 流量。一条心愿 50 字节，50MB 能存 100 万条。

**Q：担心被人刷祝福怎么办？**
A：`SUPABASE_SETUP.sql` 里已经限制单条 40 字以内。
如果真被刷了，Supabase Dashboard → Authentication → Rate Limits 可以按 IP 限流。
或者加一个简单的频率限制：同一 IP 每分钟最多 3 条。
