# Jev Guard

<video controls playsinline src="https://huggingface.co/hubin/jev-guard-v3.2-2b/resolve/main/assets/hermes-jev-demo.mp4" poster="https://huggingface.co/hubin/jev-guard-v3.2-2b/resolve/main/assets/demo-poster.png"></video>

[Watch the introduction with English/Chinese captions](https://hkust-knowcomp.github.io/jev-guardrail/#hermes)

[Website](https://hkust-knowcomp.github.io/jev-guardrail/) · [中文版](README.zh-CN.md) · [Model](https://huggingface.co/hubin/jev-guard-v3.2-2b)

Your policy tree. Jev reviews each agent step.

Maintain an editable policy tree for **content, cyber, privacy and compliance**. Route every user request and proposed tool action from the root to a leaf, then classify its **safety and category** before the harness proceeds. Users can change routing descriptions, leaf taxonomies and review rules. A blocked user request never reaches the assistant model; a blocked tool action never executes, and the interception appears in the conversation.

**Wenbin Hu · HKUST × [ModeIO](https://www.modeio.ai/)**

**93.20% full-path routing accuracy** · **91.78% overall safety accuracy** · **58.0 ms mean native forward latency**.

Routing uses 1,000 held-out cases; safety is 73,415/79,987 supervised records. Forward latency is a case-weighted mean over 147,643 records and excludes the complete routing-plus-review sequence.

## 1. A policy tree you can change

Content, cyber, privacy and compliance share one tree with 85 nodes. Each leaf holds its taxonomy and review rules. Use the website to explore/edit/export a browser-local preview. Use `/safety-policy` in Hermes to change its live rules.

<details><summary>Maintained routing tree</summary>

- `root`
  - `content`
  - `cyber`
    - `cyber.code`
    - `cyber.root_cause`
    - `cyber.severity`
    - `cyber.attack`
    - `cyber.email`
    - `cyber.web`
    - `cyber.http`
    - `cyber.injection`
    - `cyber.authorization`
    - `cyber.request`
  - `privacy`
  - `compliance`
    - `compliance.contract`
    - `compliance.law`
      - `policy.law.privacy.ccpa`
      - `policy.law.privacy.gdpr`
      - `policy.law.privacy.prc_cybersecurity`
      - `policy.law.privacy.eu_data_act`
      - `policy.law.privacy.hipaa`
      - `policy.law.privacy.eu_ai_act`
      - `policy.law.rights.eu_charter`
      - `policy.law.privacy.prc_pipl`
      - `policy.law.privacy.prc_generative_ai`
      - `policy.law.privacy.prc_data_security`
      - `policy.law.privacy.prc_deep_synthesis`
      - `policy.law.edu.title_ix`
    - `compliance.platform`
      - `compliance.platform.reddit`
        - `policy.policy.reddit.enforcement_guideline`
        - `policy.policy.reddit.advertising_agreement`
        - `policy.policy.reddit.developer`
        - `policy.policy.reddit.developer_data_protect`
        - `policy.policy.reddit.creator`
        - `policy.policy.reddit.api_terms`
        - `policy.policy.reddit.public_content`
        - `policy.policy.reddit.privacy`
        - `policy.policy.reddit.reddit_user_agreement`
        - `policy.policy.reddit.earn_terms`
        - `policy.policy.reddit.trade_mark`
        - `policy.policy.reddit.business_tools`
        - `policy.policy.reddit.ads_api`
        - `policy.policy.reddit.bug_boundy`
        - `policy.policy.reddit.embed`
        - `policy.policy.reddit.econ`
        - `policy.policy.reddit.moderation`
        - `policy.policy.reddit.reddit_foundation`
        - `policy.policy.reddit.anti_slavery`
        - `policy.policy.reddit.cookie`
      - `compliance.platform.wechat`
        - `policy.policy.wechat.service_terms`
        - `policy.policy.wechat.accept_user_policy`
        - `policy.policy.wechat.wechat_privacy`
      - `compliance.platform.github`
        - `policy.policy.github.bundle.other_site_policies`
        - `policy.policy.github.bundle.privacy_policies`
        - `policy.policy.github.bundle.github_terms`
        - `policy.policy.github.bundle.acceptable_use_policies`
        - `policy.policy.github.bundle.content_removal_policies`
        - `policy.policy.github.bundle.security_policies`
        - `policy.policy.github.bundle.github_company_policies`
      - `compliance.platform.google`
        - `policy.policy.google.google_privacy_policy`
        - `policy.policy.google.service_term`
        - `policy.policy.google.cloud_servises_term`
        - `policy.policy.google.gemma_prohibition`
        - `policy.policy.google.dev_privacy`
        - `policy.policy.google.dev_site_policy`
        - `policy.policy.google.gen_ai_terms`
      - `compliance.platform.x`
        - `policy.policy.x.xai_privacy`
        - `policy.policy.x.x_privacy`
        - `policy.policy.x.service`
      - `compliance.platform.openai`
        - `policy.policy.openai.privacy_terms`
        - `policy.policy.openai.teacher_offering`
        - `policy.policy.openai.usage_policy`
        - `policy.policy.openai.service_terms`
        - `policy.policy.openai.data_process`
    - `compliance.education`
      - `policy.policy.edu.academic_integrity`
      - `policy.policy.edu.online_learning`
      - `policy.policy.edu.academic_integrity_ai`

</details>

## 2. Route to a leaf. Review safety and category

Jev selects the highest-probability branch at each level. At the leaf, safety and category probabilities are combined with explicit authorization rules. Blocked requests stop before assistant inference; blocked actions stop before execution. The demo animates an actual decision trace and explains recorded Hermes interceptions in red.

## 3. A small classifier with typed outputs

Qwen3.5-2B with rank-8 LoRA uses the last non-padding hidden state. A two-class linear head predicts safety; candidate-embedding similarity predicts single or multiple categories and routing branches; a scalar and ordered thresholds predict severity. Text context: 16K.

| Domain | Task records | Safety-labeled records | Safety accuracy | Category micro-F1 |
|---|---:|---:|---:|---:|
| Content | 11,909 | 11,909 | 85.20% | 61.86% |
| Cyber | 61,972 | 57,478 | 93.77% | 46.96% |
| Privacy | 69,051 | 5,889 | 82.92% | 78.40% |
| Compliance | 4,711 | 4,711 | 95.31% | 58.17% |

Native tests cover 147,643 task records across 109 views and retain original v3.1 labels/candidates. Supervision denominators differ by metric and benchmark views may overlap. Controlled action-state replay caught 49/52 malicious proposals and allowed 87/97 benign proposals. This is not end-to-end attack success. The v3.2 checkpoint was selected after one continuation epoch; plateau was not established. Quoted injection analysis can be falsely blocked; some expanded categories lack positives.

## Use it with Hermes

First start the reviewer following the [model card](https://huggingface.co/hubin/jev-guard-v3.2-2b#inference). Then:

```bash
curl -fsSL https://huggingface.co/hubin/jev-guard-v3.2-2b/resolve/main/downloads/install-hermes-jev.txt -o /tmp/install-hermes-jev.sh
bash /tmp/install-hermes-jev.sh --endpoint http://127.0.0.1:29660
jev-hermes
```

Configure your provider with `hermes setup`. `/safety-policy` opens the live tree editor. The model card contains inference and installation details. This repository contains the website only.

Video: actual action-review replay and archived Hermes + DeepSeek output; AI narration (Kokoro `af_heart`), Cipher by Kevin MacLeod ([source](https://incompetech.com/music/royalty-free/index.html?isrc=USUAN1100844)), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Independent research built on Qwen, Open-Jev and Hermes.
