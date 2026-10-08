# Jev Guard

<video controls playsinline src="https://huggingface.co/hubin/jev-guard-v3.2-2b/resolve/main/assets/hermes-jev-demo.mp4" poster="https://huggingface.co/hubin/jev-guard-v3.2-2b/resolve/main/assets/demo-poster.png"></video>

[Watch the introduction with English/Chinese captions](https://hkust-knowcomp.github.io/jev-guardrail/#hermes)

[English](README.md) · [中文网站](https://hkust-knowcomp.github.io/jev-guardrail/zh/)

**Wenbin Hu · HKUST × ModeIO**

## 1. 可编辑的策略分类树

content、cyber、privacy、compliance 共享 85 个节点的树。用户可修改每层 routing 描述、叶子 taxonomy 和审核规则。网页修改保存在浏览器，Hermes 中用 `/safety-policy` 修改实际策略。

## 2. Routing 后在叶子判断 safety/category

对每个用户请求和拟执行 action 逐层选择最高概率分支，到叶子后分类。harness 再结合明确授权规则决定 allow/ask/block。被拦截的用户请求不调用大模型，被拦截的 action 不执行，拦截信息在 Hermes 对话中标红显示。

## 3. 模型架构和能力

Qwen3.5-2B + rank-8 LoRA，安全二分类头、候选 embedding 相似度分类头、标量和有序阈值程度头。文本上下文 16K。

**93.20% full-path routing accuracy** · **91.78% overall safety accuracy** · **58.0 ms mean native forward latency**.

Routing uses 1,000 held-out cases; safety is 73,415/79,987 supervised records. Forward latency is a case-weighted mean over 147,643 records and excludes the complete routing-plus-review sequence.

| Domain | Task records | Safety-labeled records | Safety accuracy | Category micro-F1 |
|---|---:|---:|---:|---:|
| Content | 11,909 | 11,909 | 85.20% | 61.86% |
| Cyber | 61,972 | 57,478 | 93.77% | 46.96% |
| Privacy | 69,051 | 5,889 | 82.92% | 78.40% |
| Compliance | 4,711 | 4,711 | 95.31% | 58.17% |

完整评测覆盖 147,643 条记录、109 个视图，使用原始 v3.1 标签和候选类别。受控回放拦截 49/52 条恶意提议，放行 87/97 条正常提议；不是端到端攻击成功率。v3.2 续训一轮，未证明平台期。

## 在 Hermes 使用

直接连接已部署的 Jev v3.2 审核服务，无需本地 GPU：

```bash
curl -fsSL https://huggingface.co/hubin/jev-guard-v3.2-2b/resolve/main/downloads/install-hermes-jev.txt -o /tmp/install-hermes-jev.sh
bash /tmp/install-hermes-jev.sh --endpoint https://approaches-lemon-antique-garden.trycloudflare.com
jev-hermes
```

用 `hermes setup` 配置 provider；输入 `/safety-policy` 编辑实际树。此 GitHub 仓库只存网站文件。模型及部署指引见模型卡，训练数据和复现代码单独管理。
