export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    const corsHeaders = {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST,OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    async function sha256(text) {
      const enc = new TextEncoder();
      const buf = await crypto.subtle.digest("SHA-256", enc.encode(text));
      return Array.from(new Uint8Array(buf))
        .map(b => b.toString(16).padStart(2, "0"))
        .join("");
    }

    if (pathname === "/register" && request.method === "POST") {
      try {
        const { email, password } = await request.json();
        if (!email || !password) {
          return Response.json({ success: false, msg: "邮箱或密码不能为空" }, { status: 400, headers: corsHeaders });
        }

        const hash = await sha256(password);
        const uid = crypto.randomUUID();

        await env.DB.prepare("INSERT INTO users (id, email, password_hash) VALUES (?, ?, ?)")
          .bind(uid, email, hash)
          .run();

        return Response.json({ success: true, msg: "注册成功" }, { headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, msg: "邮箱已被注册" }, { status: 409, headers: corsHeaders });
      }
    }

    if (pathname === "/login" && request.method === "POST") {
      try {
        const { email, password } = await request.json();
        const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?")
          .bind(email)
          .first();

        if (!user) {
          return Response.json({ success: false, msg: "用户不存在" }, { status: 404, headers: corsHeaders });
        }

        const inputHash = await sha256(password);
        if (inputHash !== user.password_hash) {
          return Response.json({ success: false, msg: "密码错误" }, { status: 401, headers: corsHeaders });
        }

        return Response.json({ success: true, msg: "登录成功" }, { headers: corsHeaders });
      } catch (e) {
        return Response.json({ success: false, msg: "服务器异常" }, { status: 500, headers: corsHeaders });
      }
    }

    return Response.json({ msg: "接口不存在" }, { status: 404, headers: corsHeaders });
  }
};
