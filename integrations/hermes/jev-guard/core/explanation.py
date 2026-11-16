"""Explain recorded decisions without evaluating policy or granting authority."""

DECISION_LABELS = {'allow': '允许', 'ask': '需要人工批准', 'block': '拦截', 'review': '参与文字审核'}
MATCH_LABELS = {'route': '分类路径命中', 'effects': '实际行为命中',
                'unresolved_effects': '行为尚未完全解析，保守纳入规则'}
STAGE_LABELS = {'user_request': '请求安全审核', 'user_request_admission': '请求准入结果',
                'action': '动作审核', 'action_error': '动作前置检查',
                'approval': '审批答复', 'execution_gate': '执行前检查'}


def explain_review(review, stage='action'):
    decision = review.get('effective_decision', 'block')
    summary = DECISION_LABELS.get(decision, decision)
    stage_label = STAGE_LABELS.get(stage, stage)
    review_stage = stage in ('user_request', 'action')
    sources = []
    covered_reasons = set()

    def add(kind, title, detail, required=None, *, historical=False, **location):
        if historical:
            title = '原审核记录 · ' + title
            detail = '仅供历史参考，不作为本阶段裁决依据。' + detail
        sources.append({'kind': kind, 'title': title, 'detail': detail,
                        'decision': required,
                        'decisive': not historical and required == decision and required in ('ask', 'block'),
                        **location})

    for check in review.get('scope_checks', []):
        keys = check.get('permission_keys', [])
        detail = check['reason']
        historical = stage in ('user_request_admission', 'approval')
        if not historical:
            covered_reasons.add(detail)
        add('permissions' if keys else 'local_check',
            ('有效权限 · ' if keys else '本地动作检查 · ') + check['category'],
            detail, check['decision'], historical=historical,
            target='permissions' if keys else None,
            permission_keys=keys,
            location='权限配置 scope / ' + ', '.join(keys) + '；会话范围另受 /jev-scope 约束' if keys else
                     '本地动作约束；旧记录可能没有具体权限字段')

    for rule in review.get('execution_rules', []):
        required = rule['decision']
        if review_stage:
            covered_reasons.add('Execution rule ' + rule['node_id'] + ' requires ' + required)
        basis = MATCH_LABELS.get(rule.get('match_basis'), '匹配依据未记录')
        effects = rule.get('matched_effects') or []
        if effects:
            basis += '：' + ', '.join(effects)
        detail = basis + '。' + (rule.get('policy') or '按节点配置执行。')
        if required == 'review':
            detail += ' 此规则参与综合审核；当前服务未返回逐条规则的判断，不能认定它单独导致拦截。'
        add('execution_rule', '策略节点 · ' + rule.get('node_label', rule['node_id']),
            detail, required, historical=not review_stage, target='node', node_id=rule['node_id'],
            location='policy/config.json / tree.nodes.' + rule['node_id'] + '.execution_rule')

    contract = review.get('request_contract')
    if contract:
        contract_block = review.get('error_type') == 'text_contract'
        add('text_contract', '当前请求的文本处理契约',
            '操作：' + str(contract.get('operation', '文本处理')) +
            '；只生成文本回复，不调用工具。来源是本次直接请求，不是另一份权限配置。',
            'block' if contract_block else None, location='当前用户请求')

    predicted = review.get('predicted_decision')
    request_policy = review.get('request_safety_policy') or {}
    threshold_mode = request_policy.get('mode') == 'unsafe_threshold'
    if predicted in ('allow', 'ask', 'block'):
        add('model', 'Jev 原始安全判断' if threshold_mode else 'Jev 综合审核意见',
            '模型建议：' + DECISION_LABELS[predicted] +
            ('。本次请求另按已配置的不安全分数阈值判定；原始标签和分数保留，未被改写。' if threshold_mode else
             '。这不是逐条规则的归因；明确的本地限制仍独立生效。'),
            None if threshold_mode else predicted, historical=not review_stage, target='policy',
            location='全局请求安全审核说明' if stage in ('user_request', 'user_request_admission') else
                     '全局审核说明及本次命中的文字执行规则')
    elif predicted == 'unavailable' or review.get('error_type') == 'reviewer_unavailable':
        add('reviewer', '审核未完成', '审核服务或审核流程失败，未取得有效授权结论。',
            'block', historical=not review_stage, location='审核服务设置及原始错误记录')

    if threshold_mode:
        add('request_threshold', '请求不安全分数阈值',
            '不安全分数：' + str(request_policy['unsafe_probability']) +
            '；阈值：' + str(request_policy['unsafe_threshold']) +
            '。分数达到阈值时拦截，低于阈值时准入；此模式不使用原决策置信度转为人工确认。'
            '准入仅允许助手处理请求，工具动作仍须独立审核。',
            request_policy['decision'], historical=stage != 'user_request', target='policy',
            location='policy/config.json / thresholds.unsafe_threshold')

    remaining = [str(reason) for reason in review.get('reasons', []) if reason not in covered_reasons]
    if remaining:
        add('runtime', stage_label + '详情', '\n'.join(remaining),
            decision if review.get('error_type') else None,
            location='当前请求、审核过程或执行前检查；不是新的可配置规则')
    if review.get('routing_warning'):
        add('classification', '分类提示', str(review['routing_warning']) +
            '。分类提示本身不授予或撤销权限。')
    if review.get('admission') == 'human_once':
        if decision == 'allow':
            add('approval', '本次请求已获人工准入', '只准入当前请求；工具动作仍须独立审核。')
        else:
            # Older records may retain the marker after the revision check failed.
            add('approval', '此前批准未形成有效准入', '本条记录最终未放行；此前批准不能覆盖后续拦截。')

    if decision == 'block':
        resolution = '当前结果为拦截。明确禁止优先于审批和放行；分类标签本身不决定授权。'
        approval = '不能用“本次允许”覆盖这个结果。须处理对应限制或审核失败，再重新审核。'
    elif decision == 'ask':
        resolution = '当前结果需要人工批准；模型允许不覆盖明确的审批要求。'
        if review.get('approval_available') is False:
            summary = '需要人工批准（交互审批关闭）'
            resolution = '审核要求人工批准；当前会话关闭交互审批，实际按阻止处理。'
            approval = '审批方式由服务设置 ask_action 管理；本条审核意见没有授予执行许可。'
        else:
            prefix = '' if review.get('approval_available') is True else '若会话已启用交互审批，'
            approval = prefix + ('本次批准只准入当前请求，不授予工具权限。' if stage == 'user_request' else
                '本次批准只对应当前操作；执行前仍核对权限、策略、参数及批准凭据。')
    else:
        resolution = '记录的结果为允许；不代表工具已经执行成功。'
        approval = ('已经通过本次执行前检查。' if stage == 'execution_gate' else
                    '具体工具动作仍受最终执行检查约束。')
    if stage == 'approval':
        summary = '已收到批准' if decision == 'allow' else '未获批准'
        resolution = ('已记录批准答复；这不代表批准凭据已通过准入或执行前检查。' if decision == 'allow' else
                      '已记录拒绝或未获批准的答复；本次答复不提供执行所需的批准凭据。')
        approval = '只说明本次审批答复。请求是否准入、工具是否可执行，分别查看对应的准入结果和执行前检查。'
    elif stage == 'user_request_admission':
        summary = '请求已准入' if decision == 'allow' else '请求未准入'
        resolution = ('当前请求已通过准入检查，可交给助手处理；工具动作仍须独立审核。' if decision == 'allow' else
                      '当前请求未获准入，未交给助手处理。')
        if decision == 'allow':
            approval = '本次批准只准入当前请求，不授予工具权限。'
        elif review.get('error_type') == 'admission_revoked':
            approval = '准入前请求或授权已变化，原审核和已有批准均已失效；须重新审核。'
        elif review.get('error_type') == 'approval_invalid':
            approval = '批准凭据缺失、过期或校验失败；收到批准答复不等于准入成功。'
        elif review.get('error_type') == 'approval_disabled':
            approval = '当前会话关闭交互审批，无法满足本次请求的审批要求。'
        else:
            approval = '本次请求未取得有效批准，不能继续交给助手处理。'
    return {'decision': decision, 'summary': summary, 'stage_label': stage_label,
            'sources': sources, 'resolution': resolution, 'approval': approval,
            'config_revision': review.get('config_revision'),
            'permissions_revision': review.get('permissions_revision')}


def format_explanation(explanation):
    lines = ['阶段：' + explanation['stage_label'],
             '决定：' + explanation['summary'], explanation['resolution']]
    revisions = [('策略树', explanation.get('config_revision')),
                 ('权限', explanation.get('permissions_revision'))]
    recorded = [name + '修订 ' + str(value) for name, value in revisions if value is not None]
    if recorded:
        lines.append('依据记录：' + '；'.join(recorded))
    for source in explanation['sources']:
        label = DECISION_LABELS.get(source.get('decision'), '说明')
        lines.append(source['title'] + '［' + label + '］：' + source['detail'])
        if source.get('location'):
            lines.append('查看位置：' + source['location'])
    lines.append('人工批准：' + explanation['approval'])
    return '\n'.join(lines)
