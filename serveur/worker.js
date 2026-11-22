/* ============================================================
   Les Délices de FA — serveur du portail (Cloudflare Worker)
   ------------------------------------------------------------
   À coller tel quel dans l'éditeur du Worker « delices-api ».
   Réglages à faire dans Cloudflare (Settings) :
     - Liaison D1   : nom « DB »  → base « delices-de-fa »
     - Secret       : ADMIN_EMAIL     (l'e-mail de Fa ; plusieurs possibles, séparés par des virgules)
     - Secret       : ADMIN_PASSWORD  (le mot de passe du portail, 10 caractères minimum)
   Aucune autre configuration n'est nécessaire.
   ============================================================ */

const CLES = ["reglages", "textes", "carte", "jus", "cremes", "galerie", "avis"];
const DUREE_SESSION = 30 * 24 * 3600; // 30 jours
const MAX_ESSAIS = 8, FENETRE_ESSAIS = 15 * 60; // 8 erreurs par 15 minutes
const TAILLE_MAX = 300 * 1024;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400",
};
const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS, ...extra } });
const erreur = (message, status = 400) => json({ erreur: message }, status);

const enc = new TextEncoder();
const b64url = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const deb64url = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
async function sha256(txt) { return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(txt))); }
function egal(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }
async function cleHmac(env) {
  // La clé de session dérive du mot de passe : changer le mot de passe déconnecte tout le monde.
  return crypto.subtle.importKey("raw", await sha256("fa-session:" + (env.ADMIN_PASSWORD || "")), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function creerJeton(env, email) {
  const charge = b64url(enc.encode(JSON.stringify({ e: email, exp: Math.floor(Date.now() / 1000) + DUREE_SESSION })));
  const sig = await crypto.subtle.sign("HMAC", await cleHmac(env), enc.encode(charge));
  return charge + "." + b64url(sig);
}
async function lireJeton(env, req) {
  const h = req.headers.get("Authorization") || "";
  const t = h.startsWith("Bearer ") ? h.slice(7) : "";
  const [charge, sig] = t.split(".");
  if (!charge || !sig) return null;
  try {
    const ok = await crypto.subtle.verify("HMAC", await cleHmac(env), deb64url(sig), enc.encode(charge));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(deb64url(charge)));
    if (!p.exp || p.exp < Date.now() / 1000) return null;
    if (!emails(env).includes(String(p.e).toLowerCase())) return null;
    return p;
  } catch { return null; }
}
const emails = (env) => String(env.ADMIN_EMAIL || "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

/* Contrôle léger de la forme des données, pour éviter qu'une erreur casse le site */
function valider(cle, v) {
  if (!v || typeof v !== "object" || Array.isArray(v)) return "Données invalides.";
  const liste = (nom) => Array.isArray(v[nom]) || `Le champ « ${nom} » doit être une liste.`;
  switch (cle) {
    case "carte": {
      const l = liste("produits"); if (l !== true) return l;
      for (const p of v.produits) {
        if (!p.nom || typeof p.nom !== "string") return "Chaque produit doit avoir un nom.";
        if (!Array.isArray(p.formats) || !p.formats.length) return `« ${p.nom} » doit avoir au moins un prix.`;
        for (const f of p.formats) if (!(Number(f.prix) >= 0)) return `Prix invalide pour « ${p.nom} ».`;
      }
      return true;
    }
    case "cremes": { const l = liste("cremes"); if (l !== true) return l; return v.cremes.every((c) => c.nom) || "Chaque crème doit avoir un nom."; }
    case "jus": return liste("chapitres");
    case "galerie": return liste("photos");
    case "avis": return liste("avis");
    case "reglages": return /^\d{9,15}$/.test(String(v.whatsapp || "")) || "Le numéro WhatsApp doit contenir uniquement des chiffres (ex. 221778030157).";
    default: return true;
  }
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const chemin = url.pathname.replace(/\/+$/, "") || "/";
    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    if (!env.DB) return erreur("Base de données non reliée : ajoutez la liaison D1 « DB ».", 500);

    try {
      /* ---- lecture publique : tout le catalogue en une seule requête ---- */
      if (req.method === "GET" && chemin === "/donnees") {
        const { results } = await env.DB.prepare("SELECT cle, valeur, maj FROM docs").all();
        const out = {}; let maj = "";
        for (const r of results) { try { out[r.cle] = JSON.parse(r.valeur); if (r.maj > maj) maj = r.maj; } catch {} }
        return json({ donnees: out, maj });
      }

      /* ---- connexion ---- */
      if (req.method === "POST" && chemin === "/connexion") {
        if (!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD) return erreur("Le portail n'est pas encore configuré (e-mail et mot de passe).", 500);
        const ip = req.headers.get("CF-Connecting-IP") || "inconnue";
        const now = Math.floor(Date.now() / 1000);
        await env.DB.prepare("DELETE FROM tentatives WHERE date < ?1").bind(now - FENETRE_ESSAIS).run();
        const { n } = await env.DB.prepare("SELECT COUNT(*) AS n FROM tentatives WHERE ip = ?1").bind(ip).first();
        if (n >= MAX_ESSAIS) return erreur("Trop d'essais. Réessayez dans 15 minutes.", 429);
        let corps = {}; try { corps = await req.json(); } catch {}
        const email = String(corps.email || "").trim().toLowerCase();
        const okEmail = emails(env).includes(email);
        const okMdp = egal(await sha256(String(corps.motdepasse || "")), await sha256(String(env.ADMIN_PASSWORD)));
        if (!okEmail || !okMdp) {
          await env.DB.prepare("INSERT INTO tentatives (ip, date) VALUES (?1, ?2)").bind(ip, now).run();
          return erreur("E-mail ou mot de passe incorrect.", 401);
        }
        await env.DB.prepare("DELETE FROM tentatives WHERE ip = ?1").bind(ip).run();
        return json({ jeton: await creerJeton(env, email), email });
      }

      /* ---- tout ce qui suit demande d'être connecté ---- */
      const session = await lireJeton(env, req);
      if (!session) return erreur("Session expirée : reconnectez-vous.", 401);

      if (req.method === "GET" && chemin === "/moi") return json({ email: session.e });

      const m = chemin.match(/^\/donnees\/([a-z]+)$/);
      if (m && req.method === "PUT") {
        const cle = m[1];
        if (!CLES.includes(cle)) return erreur("Section inconnue.", 404);
        const brut = await req.text();
        if (brut.length > TAILLE_MAX) return erreur("Données trop volumineuses.", 413);
        let v; try { v = JSON.parse(brut); } catch { return erreur("Données illisibles."); }
        const ok = valider(cle, v); if (ok !== true) return erreur(ok);
        const valeur = JSON.stringify(v);
        const ancien = await env.DB.prepare("SELECT valeur FROM docs WHERE cle = ?1").bind(cle).first();
        const lots = [env.DB.prepare("INSERT INTO docs (cle, valeur, maj) VALUES (?1, ?2, datetime('now')) ON CONFLICT(cle) DO UPDATE SET valeur = excluded.valeur, maj = excluded.maj").bind(cle, valeur)];
        if (ancien && ancien.valeur !== valeur) {
          lots.push(env.DB.prepare("INSERT INTO historique (cle, valeur) VALUES (?1, ?2)").bind(cle, ancien.valeur));
          lots.push(env.DB.prepare("DELETE FROM historique WHERE cle = ?1 AND id NOT IN (SELECT id FROM historique WHERE cle = ?1 ORDER BY id DESC LIMIT 30)").bind(cle));
        }
        await env.DB.batch(lots);
        return json({ ok: true });
      }

      const h = chemin.match(/^\/historique\/([a-z]+)$/);
      if (h && req.method === "GET") {
        if (!CLES.includes(h[1])) return erreur("Section inconnue.", 404);
        const { results } = await env.DB.prepare("SELECT id, date FROM historique WHERE cle = ?1 ORDER BY id DESC LIMIT 30").bind(h[1]).all();
        return json({ versions: results });
      }
      const r = chemin.match(/^\/historique\/([a-z]+)\/(\d+)\/restaurer$/);
      if (r && req.method === "POST") {
        const v = await env.DB.prepare("SELECT valeur FROM historique WHERE cle = ?1 AND id = ?2").bind(r[1], Number(r[2])).first();
        if (!v) return erreur("Version introuvable.", 404);
        const actuel = await env.DB.prepare("SELECT valeur FROM docs WHERE cle = ?1").bind(r[1]).first();
        const lots = [env.DB.prepare("UPDATE docs SET valeur = ?2, maj = datetime('now') WHERE cle = ?1").bind(r[1], v.valeur)];
        if (actuel) lots.push(env.DB.prepare("INSERT INTO historique (cle, valeur) VALUES (?1, ?2)").bind(r[1], actuel.valeur));
        await env.DB.batch(lots);
        return json({ ok: true });
      }

      return erreur("Adresse inconnue.", 404);
    } catch (e) {
      return erreur("Erreur du serveur : " + (e && e.message ? e.message : "inconnue"), 500);
    }
  },
};
