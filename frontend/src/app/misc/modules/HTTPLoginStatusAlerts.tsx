import { AlertTriangle, ShieldCheck } from "lucide-react";

export function HTTPLoginBruteforceAlert({ bruteforceCount }: { bruteforceCount: number }) {
  return (
    <div className="rounded-xl border border-rose-200 bg-rose-50/80 p-4 text-sm text-rose-800 shadow-sm">
      <div className="flex items-center gap-2 font-semibold">
        <AlertTriangle className="h-4 w-4" />
        发现疑似爆破 / 批量验证
      </div>
      <div className="mt-2 text-[13px] leading-relaxed">
        当前结果中共有 {bruteforceCount} 个认证端点命中爆破特征，建议优先回到 HTTP
        流追踪页复核失败序列、用户名变化和限速/验证码响应。
      </div>
    </div>
  );
}

export function HTTPLoginSuccessHint() {
  return (
    <div className="rounded-xl border border-emerald-200 bg-emerald-50/70 p-4 text-sm text-emerald-800 shadow-sm">
      <div className="flex items-center gap-2 font-semibold">
        <ShieldCheck className="h-4 w-4" />
        已识别成功认证信号
      </div>
      <div className="mt-2 text-[13px] leading-relaxed">
        成功线索通常来自 2xx/3xx + Set-Cookie、token 返回或跳转到非登录页面。你可以结合包号和 stream
        继续向下追踪后续会话行为。
      </div>
    </div>
  );
}
