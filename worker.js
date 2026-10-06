// Cloudflare Worker: POST /api/verify
// Valida el token de Turnstile con la Secret Key (variable TURNSTILE_SECRET_KEY)
// y solo entonces entrega el contenido protegido de cada página.

const CONTENT = {
  tutoriales: {
    video: { id: 'F_cdxq9RNrY' }
  },
  index: {
    modules: [
      { n: 2, id: 'rVdRQhKXJT8', title: 'Cómo configurar tus márgenes de ganancias',
        note: 'Los márgenes aplicados son solo de prueba para ejemplificar. Los cálculos y márgenes aplicados a los productos son en su totalidad independientes: se aplica la estrategia del vendedor.',
        desc: 'Cómo configurar tus márgenes de ganancias y compartir tu tienda.' },
      { n: 3, id: 'X-fHb4V8ing', title: 'Editar márgenes y crear promociones',
        desc: 'Cómo editar tus márgenes de ganancias y crear tus promociones.' },
      { n: 4, id: 'uJUODiwrqu0', title: 'Producto de regalo',
        desc: 'Cómo configurar un producto de regalo.' },
      { n: 5, id: 'Vl4-iUk5PUw', title: 'Precios manuales y compartir de manera individual',
        desc: 'Cómo editar y configurar precios manuales y compartir un producto de manera individual.' }
    ]
  }
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store'
    }
  });
}

async function verify({ request, env }) {
  if (!env.TURNSTILE_SECRET_KEY) {
    return json({ ok: false, error: 'missing_secret' }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: 'bad_request' }, 400);
  }

  const token = typeof body.token === 'string' ? body.token : '';
  const page = typeof body.page === 'string' ? body.page : '';
  if (!token || token.length > 2048 || !Object.prototype.hasOwnProperty.call(CONTENT, page)) {
    return json({ ok: false, error: 'bad_request' }, 400);
  }

  const form = new FormData();
  form.append('secret', env.TURNSTILE_SECRET_KEY);
  form.append('response', token);
  const ip = request.headers.get('CF-Connecting-IP');
  if (ip) form.append('remoteip', ip);

  let outcome;
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form
    });
    outcome = await res.json();
  } catch {
    return json({ ok: false, error: 'verify_unavailable' }, 502);
  }

  if (!outcome.success) {
    const codes = Array.isArray(outcome['error-codes']) ? outcome['error-codes'].join(',') : '';
    return json({ ok: false, error: 'invalid_token' + (codes ? ':' + codes : '') }, 403);
  }

  // El token debe haberse generado en este mismo dominio
  const host = new URL(request.url).hostname;
  if (outcome.hostname && outcome.hostname !== host) {
    return json({ ok: false, error: 'invalid_hostname' }, 403);
  }

  return json({ ok: true, ...CONTENT[page] });
}

// Worker: /api/verify valida Turnstile; todo lo demás se sirve como archivos estáticos
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/api/verify') {
      if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
      return verify({ request, env });
    }
    return env.ASSETS.fetch(request);
  }
};
