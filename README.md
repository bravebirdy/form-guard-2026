# form-guard-2026
form-guard 是一个基于 FastAPI + PostgreSQL 的轻量级限流服务，用于限制前端表单（form_key）在 IP 维度的提交频率。它采用滑动 60 分钟窗口统计成功提交次数，在提交前提供校验接口（超限返回 429），在提交成功后记录事件；同时支持按 IP/CIDR 配置覆盖规则，0 次/小时 可直接屏蔽指定 IP 或网段。

## form-guard

FastAPI + PostgreSQL service to rate-limit frontend form submissions by **IP + form_key** using a **rolling 60-minute window**, with **CIDR override rules** and **0/hour = block**.

### Quick start (Docker)

```bash
bash ./install-docker.sh
```


### API

- `POST /v1/rate-limit/check`
- `POST /v1/rate-limit/record`

### Example requests

```bash
curl -sS -X POST "http://localhost:8000/v1/rate-limit/check" \
  -H "Content-Type: application/json" \
  -d '{"form_key":"contact_us"}' | jq .
```


